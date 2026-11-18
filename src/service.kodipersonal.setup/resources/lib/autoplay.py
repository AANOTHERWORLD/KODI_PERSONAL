# -*- coding: utf-8 -*-
# KODI_PERSONAL build: Up Next autoplay fallback.
#
# What it does
#   When an episode finishes on its own (not when you press stop), Red Light gets
#   the first chance to play the next episode of the same show. If nothing has
#   started after a short quiet period, this module takes over:
#     1. If the same show has a next episode that has already aired, play it.
#        (Covers devices where Red Light's own next-episode autoplay is off.)
#     2. Otherwise the show is caught up, so play the next show in the For You
#        Up Next row, in the order the row had when the episode started.
#   A cancellable countdown shows what is coming. After a set number of
#   automatic plays in a row it asks "Still watching?" instead.
#
# Why the Up Next row is copied when an episode STARTS
#   Once an episode finishes, Red Light marks it watched on Trakt and the Up Next
#   row reorders or drops the show. The copy taken at start keeps "the show after
#   this one" stable.
#
# Threading
#   Kodi delivers xbmc.Player callbacks while the service waits in its idle loop.
#   The callbacks only record events; all JSON-RPC and dialog work happens in
#   tick(), which the service calls from that loop once a second.
#
# Logging is verbose by design: every decision lands in kodipersonal.log with
# the prefix "Autoplay:".

import time
from urllib.parse import urlencode, parse_qsl, urlsplit

import xbmc
import xbmcgui

TMDBH_BASE = 'plugin://plugin.video.themoviedb.helper/'
UP_NEXT_PATH = TMDBH_BASE + '?info=trakt_nextepisodes&tmdb_type=tv'

# Quiet period after a natural end before we act, so Red Light can start the
# next episode itself. While a busy or progress dialog is open (Red Light
# scraping sources) the wait is extended, up to the hard cap.
QUIET_SECONDS = 8
MAX_WAIT_SECONDS = 60
# An AV start this soon after we fired a play counts as our autoplay, so the
# chain counter keeps counting instead of resetting.
OUR_PLAY_WINDOW_SECONDS = 180
# How long the "Still watching?" prompt waits before giving up (no autoplay).
STILL_WATCHING_TIMEOUT_MS = 60000

DIRECTORY_PROPS = ['showtitle', 'season', 'episode', 'uniqueid', 'title',
                   'firstaired', 'file']
PLAYER_PROPS = ['showtitle', 'season', 'episode', 'uniqueid', 'title', 'file']


def _norm(title):
    return ''.join(ch for ch in (title or '').lower() if ch.isalnum())


def _query(path):
    try:
        return dict(parse_qsl(urlsplit(path or '').query))
    except Exception:  # noqa: BLE001
        return {}


def _as_int(value, default=-1):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class _Player(xbmc.Player):
    # Records events only. No JSON-RPC or dialogs here.
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def onAVStarted(self):
        self.owner.events.append(('started', time.time()))

    def onPlayBackEnded(self):
        self.owner.events.append(('ended', time.time()))

    def onPlayBackStopped(self):
        self.owner.events.append(('stopped', time.time()))

    def onPlayBackError(self):
        self.owner.events.append(('stopped', time.time()))


class UpNextAutoplay(object):
    def __init__(self, addon, log, jsonrpc, monitor):
        self.addon = addon
        self.log = log
        self.jsonrpc = jsonrpc
        self.monitor = monitor
        self.events = []
        self.current = None        # episode now playing (dict) or None
        self.snapshot = []         # Up Next copy taken when it started
        self.pending_end = None    # time of a natural end we are waiting on
        self.chain = 0             # automatic plays in a row
        self.visited = set()       # shows already played in this chain
        self.last_fired = 0.0
        self.player = _Player(self)
        self.log('Autoplay: monitor ready (enabled={}, countdown={}s, '
                 'still-watching after {}, wrap={}).'.format(
                     self._enabled(), self._countdown(), self._chain_limit(),
                     self._wrap()))

    # ---- settings ---------------------------------------------------------

    def _enabled(self):
        try:
            return self.addon.getSettingBool('autoplay_enabled')
        except Exception:  # noqa: BLE001
            return True

    def _countdown(self):
        try:
            return max(3, min(60, self.addon.getSettingInt('autoplay_countdown')))
        except Exception:  # noqa: BLE001
            return 10

    def _chain_limit(self):
        try:
            return max(1, min(20, self.addon.getSettingInt('autoplay_chain_limit')))
        except Exception:  # noqa: BLE001
            return 3

    def _wrap(self):
        try:
            return self.addon.getSettingBool('autoplay_wrap')
        except Exception:  # noqa: BLE001
            return False

    # ---- main loop hook ---------------------------------------------------

    def tick(self):
        while self.events:
            kind, stamp = self.events.pop(0)
            if kind == 'started':
                self._on_started(stamp)
            elif kind == 'ended':
                self._on_ended(stamp)
            else:
                self._on_stopped()
        if self.pending_end is not None:
            self._check_pending()

    # ---- event handlers ---------------------------------------------------

    def _on_started(self, stamp):
        if self.pending_end is not None:
            self.log('Autoplay: playback started during the quiet period '
                     '(Red Light or you picked the next item); standing down.')
            self.pending_end = None
        ours = (stamp - self.last_fired) <= OUR_PLAY_WINDOW_SECONDS
        if not ours and (self.chain or self.visited):
            self.log('Autoplay: manual start; chain counter reset.')
            self.chain = 0
            self.visited = set()
        self.current = self._playing_episode()
        if not self.current:
            self.snapshot = []
            return
        self.log('Autoplay: watching {} S{:02d}E{:02d} (tmdb {}).'.format(
            self.current['showtitle'], self.current['season'],
            self.current['episode'], self.current.get('tmdb_id') or 'unknown'))
        if not self._enabled():
            self.log('Autoplay: disabled in settings; not reading Up Next.')
            self.snapshot = []
            return
        self.snapshot = self._read_up_next()
        self.log('Autoplay: saved Up Next order ({} shows): {}'.format(
            len(self.snapshot),
            ', '.join(item['showtitle'] for item in self.snapshot[:12]) or 'empty'))

    def _on_ended(self, stamp):
        if not self.current:
            self.log('Autoplay: playback ended, but it was not an episode; nothing to do.')
            return
        if not self._enabled():
            self.log('Autoplay: episode ended; autoplay is off in settings.')
            return
        self.log('Autoplay: {} S{:02d}E{:02d} ended on its own; waiting for Red Light.'.format(
            self.current['showtitle'], self.current['season'], self.current['episode']))
        self.pending_end = stamp

    def _on_stopped(self):
        if self.current:
            self.log('Autoplay: playback stopped by the user or an error; no autoplay.')
        self.pending_end = None
        self.current = None

    # ---- the quiet period -------------------------------------------------

    def _busy(self):
        return (xbmc.getCondVisibility('Window.IsActive(busydialog)') or
                xbmc.getCondVisibility('Window.IsActive(busydialognocancel)') or
                xbmc.getCondVisibility('Window.IsActive(progressdialog)') or
                xbmc.getCondVisibility('Window.IsActive(extendedprogressdialog)'))

    def _check_pending(self):
        now = time.time()
        waited = now - self.pending_end
        if xbmc.Player().isPlaying():
            self.log('Autoplay: something is playing again; standing down.')
            self.pending_end = None
            return
        if waited > MAX_WAIT_SECONDS:
            self.log('Autoplay: waited {}s with a dialog open and nothing started; '
                     'giving up.'.format(MAX_WAIT_SECONDS))
            self.pending_end = None
            return
        if self._busy():
            return  # Red Light may be finding sources; keep waiting
        if waited < QUIET_SECONDS:
            return
        self.pending_end = None
        self._fallback()

    # ---- deciding what to play --------------------------------------------

    def _fallback(self):
        ended = self.current
        self.current = None
        if not ended:
            return
        self.log('Autoplay: nothing started {}s after the end; choosing what is next.'.format(
            QUIET_SECONDS))
        self.visited.add(_norm(ended['showtitle']))

        target = self._same_show_next(ended)
        if target:
            self.log('Autoplay: {} has an aired next episode, S{:02d}E{:02d}; '
                     'playing that (Red Light did not continue).'.format(
                         ended['showtitle'], target['season'], target['episode']))
        else:
            target = self._next_show(ended)
        if not target:
            self.log('Autoplay: nothing left to play in Up Next; stopping.')
            return

        if self.chain >= self._chain_limit():
            if not self._still_watching(target):
                self.log('Autoplay: "Still watching?" not confirmed; stopping.')
                self.chain = 0
                self.visited = set()
                return
            self.chain = 0
        elif not self._countdown_dialog(target):
            self.log('Autoplay: countdown cancelled; stopping.')
            return
        self._play(target)

    def _show_tmdb_id(self, ended):
        # The Up Next row's id comes from TMDb Helper's play path and is always
        # the show id, so it wins. Red Light's own id is the fallback.
        key = _norm(ended['showtitle'])
        for item in self.snapshot:
            if _norm(item['showtitle']) == key and item.get('tmdb_id'):
                return item['tmdb_id']
        return ended.get('tmdb_id') or ''

    def _aired(self, firstaired):
        if not firstaired:
            return False
        return firstaired[:10] <= time.strftime('%Y-%m-%d')

    def _season_episodes(self, tmdb_id, season):
        path = TMDBH_BASE + '?' + urlencode({
            'info': 'episodes', 'tmdb_type': 'tv', 'tmdb_id': tmdb_id, 'season': season})
        return self._directory(path)

    def _same_show_next(self, ended):
        tmdb_id = self._show_tmdb_id(ended)
        if not tmdb_id:
            self.log('Autoplay: no TMDb id for {}; cannot check for its next episode, '
                     'moving on in Up Next.'.format(ended['showtitle']))
            return None
        season, episode = ended['season'], ended['episode']
        for check_season, after in ((season, episode), (season + 1, 0)):
            items = self._season_episodes(tmdb_id, check_season)
            wrong = [i for i in items if i['showtitle'] and
                     _norm(i['showtitle']) != _norm(ended['showtitle'])]
            if wrong:
                self.log('Autoplay: TMDb id {} lists episodes of {}, not {}; '
                         'skipping the same-show check.'.format(
                             tmdb_id, wrong[0]['showtitle'], ended['showtitle']),
                         xbmc.LOGWARNING)
                return None
            later = sorted((i for i in items
                            if i['season'] == check_season and i['episode'] > after),
                           key=lambda i: i['episode'])
            if later:
                nxt = later[0]
                if self._aired(nxt.get('firstaired')):
                    return {'showtitle': ended['showtitle'], 'tmdb_id': tmdb_id,
                            'season': nxt['season'], 'episode': nxt['episode'], 'file': ''}
                self.log('Autoplay: {} next episode S{:02d}E{:02d} airs {}; show is caught up.'.format(
                    ended['showtitle'], nxt['season'], nxt['episode'],
                    nxt.get('firstaired') or 'on an unknown date'))
                return None
        self.log('Autoplay: {} has no later episodes listed; show is caught up.'.format(
            ended['showtitle']))
        return None

    def _next_show(self, ended):
        if not self.snapshot:
            self.log('Autoplay: the saved Up Next copy is empty.')
            return None
        key = _norm(ended['showtitle'])
        index = next((n for n, item in enumerate(self.snapshot)
                      if _norm(item['showtitle']) == key), None)
        if index is None:
            self.log('Autoplay: {} was not in Up Next; starting from the top of the row.'.format(
                ended['showtitle']))
            candidates = list(self.snapshot)
        else:
            candidates = self.snapshot[index + 1:]
            if self._wrap():
                candidates += self.snapshot[:index]
        for item in candidates:
            if _norm(item['showtitle']) in self.visited:
                self.log('Autoplay: skipping {} (already played in this run).'.format(
                    item['showtitle']))
                continue
            self.log('Autoplay: next show in Up Next is {} S{:02d}E{:02d}.'.format(
                item['showtitle'], item['season'], item['episode']))
            return item
        return None

    # ---- dialogs ----------------------------------------------------------

    def _label(self, target):
        return '{}  S{:02d}E{:02d}'.format(target['showtitle'], target['season'],
                                           target['episode'])

    def _countdown_dialog(self, target):
        seconds = self._countdown()
        dialog = xbmcgui.DialogProgress()
        dialog.create('Up next', self._label(target))
        try:
            for remaining in range(seconds, 0, -1):
                dialog.update(int(100 * (seconds - remaining) / seconds),
                              '{}[CR]Playing in {}s. Cancel to stop.'.format(
                                  self._label(target), remaining))
                for _ in range(4):
                    if dialog.iscanceled():
                        return False
                    if xbmc.Player().isPlaying():
                        self.log('Autoplay: something started during the countdown; '
                                 'standing down.')
                        return False
                    if self.monitor.waitForAbort(0.25):
                        return False
            return True
        finally:
            dialog.close()

    def _still_watching(self, target):
        self.log('Autoplay: {} automatic plays in a row; asking "Still watching?".'.format(
            self.chain))
        return xbmcgui.Dialog().yesno(
            'Still watching?',
            'Up next: {}'.format(self._label(target)),
            nolabel='Stop', yeslabel='Keep watching',
            autoclose=STILL_WATCHING_TIMEOUT_MS)

    # ---- playing ----------------------------------------------------------

    def _play_url(self, target):
        params = _query(target.get('file'))
        if params.get('info') == 'play' and params.get('tmdb_id'):
            return target['file']
        tmdb_id = target.get('tmdb_id') or params.get('tmdb_id')
        if tmdb_id:
            return TMDBH_BASE + '?' + urlencode({
                'info': 'play', 'tmdb_type': 'tv', 'tmdb_id': tmdb_id,
                'season': target['season'], 'episode': target['episode']})
        return target.get('file') or ''

    def _play(self, target):
        url = self._play_url(target)
        if not url:
            self.log('Autoplay: no playable path for {}; stopping.'.format(
                self._label(target)), xbmc.LOGWARNING)
            return
        self.chain += 1
        self.visited.add(_norm(target['showtitle']))
        self.last_fired = time.time()
        self.log('Autoplay: playing {} (automatic play {} in a row) via {}'.format(
            self._label(target), self.chain, url))
        xbmc.executebuiltin('PlayMedia({})'.format(url))

    # ---- reading Kodi -----------------------------------------------------

    def _ids(self, item):
        # Show-level TMDb id: from the item's play path first, then uniqueids.
        params = _query(item.get('file'))
        uid = item.get('uniqueid') or {}
        return (params.get('tmdb_id') or uid.get('tvshow.tmdb') or
                uid.get('tmdb_tvshow') or '')

    def _directory(self, path):
        response = self.jsonrpc('Files.GetDirectory', {
            'directory': path, 'media': 'video', 'properties': DIRECTORY_PROPS})
        if 'error' in response:
            self.log('Autoplay: could not list {}: {}'.format(
                path, response['error']), xbmc.LOGWARNING)
            return []
        items = []
        for raw in (response.get('result') or {}).get('files') or []:
            season = _as_int(raw.get('season'))
            episode = _as_int(raw.get('episode'))
            if season < 0 or episode < 0:
                continue
            items.append({
                'showtitle': raw.get('showtitle') or raw.get('label') or '',
                'season': season, 'episode': episode,
                'firstaired': raw.get('firstaired') or '',
                'file': raw.get('file') or '',
                'tmdb_id': self._ids(raw)})
        return items

    def _read_up_next(self):
        items = [i for i in self._directory(UP_NEXT_PATH) if i['showtitle']]
        seen, ordered = set(), []
        for item in items:  # one entry per show, row order kept
            key = _norm(item['showtitle'])
            if key not in seen:
                seen.add(key)
                ordered.append(item)
        return ordered

    def _playing_episode(self):
        players = (self.jsonrpc('Player.GetActivePlayers', {}).get('result') or [])
        video = next((p for p in players if p.get('type') == 'video'), None)
        if not video:
            return None
        item = (self.jsonrpc('Player.GetItem', {
            'playerid': video.get('playerid', 1),
            'properties': PLAYER_PROPS}).get('result') or {}).get('item') or {}
        season = _as_int(item.get('season'))
        episode = _as_int(item.get('episode'))
        showtitle = item.get('showtitle') or ''
        if not showtitle or season < 0 or episode < 1:
            self.log('Autoplay: now playing is not a TV episode (type {}); ignoring.'.format(
                item.get('type') or 'unknown'))
            return None
        uid = item.get('uniqueid') or {}
        # Red Light episode items usually carry the show's TMDb id as "tmdb";
        # prefer an explicit show id when one is present.
        tmdb_id = uid.get('tvshow.tmdb') or uid.get('tmdb_tvshow') or uid.get('tmdb') or ''
        return {'showtitle': showtitle, 'season': season, 'episode': episode,
                'tmdb_id': str(tmdb_id) if tmdb_id else ''}
