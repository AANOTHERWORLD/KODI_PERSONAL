#$pyFunction
def GetLSProData(page_data,Cookie_Jar,m,url = ''):
    from resources.lib.modules import client,control
    if not control.infoLabel('Container.PluginName') == 'plugin.video.thecrew': return
    url = client.schedule('http://tv247.us/all-channels/')
    return url