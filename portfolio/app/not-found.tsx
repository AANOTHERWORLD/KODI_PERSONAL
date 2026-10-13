import Link from "next/link";

export default function NotFound() {
  return (
    <div className="wrap">
      <section className="hero">
        <p className="kicker">404</p>
        <h1 className="hero__headline">That page is elsewhere</h1>
        <p className="hero__positioning">The address may have changed, or the project is still awaiting permission to publish.</p>
        <div className="hero__actions">
          <Link href="/work/" className="button" data-cursor="ring">Selected work</Link>
          <Link href="/" className="text-link">Home</Link>
        </div>
      </section>
    </div>
  );
}
