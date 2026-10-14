import Link from "next/link";

export default function NotFound() {
  return (
    <div className="wrap">
      <section className="page-head">
        <p className="tag">404</p>
        <h1 className="page-head__title">That page is elsewhere</h1>
        <p className="lede">The address may have changed, or the page may have moved. Try the work index or the home page.</p>
        <div className="actions">
          <Link href="/work/" className="button" data-sweep>Work</Link>
          <Link href="/" className="text-link" data-sweep>Home</Link>
        </div>
      </section>
    </div>
  );
}
