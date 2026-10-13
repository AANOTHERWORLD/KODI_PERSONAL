export default function DraftBadge({ note }: { note?: string }) {
  return (
    <p className="draft-marker draft-marker--block" role="note">
      Draft: permission pending{note ? `. ${note}` : ""}
    </p>
  );
}
