export function BrandMark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" aria-hidden="true" className="brand-mark">
      <rect width="28" height="28" rx="7" fill="#12141f" stroke="#2b3042" strokeWidth="1" />
      <path d="M7 19.5c3.6-.3 5.4-2.4 6.3-5.6.5-1.8 1.9-3.2 4-3.4L21 10l-1.5 2.3c1 .2 1.6.8 1.8 1.7-1.5-.4-2.6 0-3.2 1.1-1 2-3.3 4.2-8.1 4.4z" fill="#fff" />
      <path d="M13.8 22c.2-1.8 1.3-3 3.2-3.6-.1 1.6-.8 2.8-3.2 3.6z" fill="#e8501a" />
    </svg>
  );
}
