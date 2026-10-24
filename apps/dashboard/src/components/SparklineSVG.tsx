import { useId } from "preact/hooks";

export interface SparklineProps {
  data: number[];
  color?: "emerald" | "cyan" | "amber" | "crimson" | "purple";
  height?: number;
  max?: number;
  min?: number;
}

const COLOR_MAP: Record<
  NonNullable<SparklineProps["color"]>,
  { stroke: string; stopTop: string; stopBottom: string }
> = {
  emerald: {
    stroke: "#34d399",
    stopTop: "rgba(52, 211, 153, 0.34)",
    stopBottom: "rgba(52, 211, 153, 0.0)",
  },
  cyan: {
    stroke: "#22d3ee",
    stopTop: "rgba(34, 211, 238, 0.34)",
    stopBottom: "rgba(34, 211, 238, 0.0)",
  },
  amber: {
    stroke: "#fbbf24",
    stopTop: "rgba(251, 191, 36, 0.34)",
    stopBottom: "rgba(251, 191, 36, 0.0)",
  },
  crimson: {
    stroke: "#f87171",
    stopTop: "rgba(248, 113, 113, 0.34)",
    stopBottom: "rgba(248, 113, 113, 0.0)",
  },
  purple: {
    stroke: "#a78bfa",
    stopTop: "rgba(167, 139, 250, 0.34)",
    stopBottom: "rgba(167, 139, 250, 0.0)",
  },
};

export function SparklineSVG({
  data,
  color = "emerald",
  height = 34,
  max,
  min,
}: SparklineProps) {
  const gradId = useId();
  const pts = data && data.length >= 2 ? data : [0, 0, 0, 0, 0, 0];
  const width = 200;
  const padY = 3;
  const lo = min !== undefined ? min : Math.min(...pts);
  const hi = max !== undefined ? max : Math.max(...pts, lo + 1e-6);
  const span = Math.max(1e-6, hi - lo);

  const coords = pts.map((v, idx) => {
    const x = (idx / Math.max(1, pts.length - 1)) * width;
    const norm = Math.max(0, Math.min(1, (v - lo) / span));
    const y = height - padY - norm * (height - padY * 2);
    return [Number(x.toFixed(1)), Number(y.toFixed(1))] as const;
  });

  const linePath = coords
    .map(([x, y], idx) => `${idx === 0 ? "M" : "L"}${x},${y}`)
    .join(" ");
  const areaPath = `${linePath} L${width},${height} L0,${height} Z`;
  const last = coords[coords.length - 1];
  const palette = COLOR_MAP[color] || COLOR_MAP.emerald;

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      class="w-full overflow-visible block"
      style={{ height: `${height}px` }}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color={palette.stopTop} />
          <stop offset="100%" stop-color={palette.stopBottom} />
        </linearGradient>
      </defs>
      <path d={areaPath} fill={`url(#${gradId})`} />
      <path
        d={linePath}
        fill="none"
        stroke={palette.stroke}
        stroke-width="1.6"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
      {last && (
        <circle
          cx={last[0]}
          cy={last[1]}
          r="2.4"
          fill={palette.stroke}
        />
      )}
    </svg>
  );
}

export default SparklineSVG;
