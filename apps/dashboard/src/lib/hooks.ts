import { useCallback, useEffect, useRef, useState } from "preact/hooks";
import { ApiError, wsUrl } from "./api";

export interface Resource<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
  loadedAt: number | null;
  reload: () => void;
}

/** Fetch on mount (and when deps change); keeps the last good data visible while reloading. */
export function useResource<T>(loader: () => Promise<T>, deps: unknown[] = [], refreshMs?: number): Resource<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState<number | null>(null);
  const seq = useRef(0);

  const reload = useCallback(() => {
    const mine = ++seq.current;
    setLoading(true);
    loader()
      .then((d) => {
        if (mine !== seq.current) return;
        setData(d);
        setError(null);
        setLoadedAt(Date.now());
      })
      .catch((e) => {
        if (mine !== seq.current) return;
        setError(e instanceof ApiError ? e : new ApiError("server", 0, String(e)));
      })
      .finally(() => {
        if (mine === seq.current) setLoading(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    reload();
    if (!refreshMs) return;
    const id = setInterval(reload, refreshMs);
    return () => clearInterval(id);
  }, [reload, refreshMs]);

  return { data, error, loading, loadedAt, reload };
}

/** Re-render every `everyMs` so "há Xs" labels and staleness stay current. */
export function useNow(everyMs = 1000): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), everyMs);
    return () => clearInterval(id);
  }, [everyMs]);
  return now;
}

export type SocketState = "connecting" | "open" | "reconnecting" | "closed";

export interface LiveSocket<T> {
  data: T | null;
  receivedAt: number | null;
  state: SocketState;
  attempt: number;
  nextRetryAt: number | null;
  lastError: string | null;
  send: (msg: string) => void;
}

const BACKOFF_STEPS_MS = [1000, 2000, 4000, 8000, 15000, 30000];

/**
 * WebSocket with exponential backoff (1s → 30s, jittered) and automatic reconnect.
 * `select` extracts the payload from each message; return undefined to ignore one.
 */
export function useLiveSocket<T>(path: string | null, select: (msg: any) => T | undefined): LiveSocket<T> {
  const [data, setData] = useState<T | null>(null);
  const [receivedAt, setReceivedAt] = useState<number | null>(null);
  const [state, setState] = useState<SocketState>("connecting");
  const [attempt, setAttempt] = useState(0);
  const [nextRetryAt, setNextRetryAt] = useState<number | null>(null);
  const [lastError, setLastError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const selectRef = useRef(select);
  selectRef.current = select;

  useEffect(() => {
    if (!path) {
      setState("closed");
      return;
    }
    const target = path;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let tries = 0;

    const connect = () => {
      if (stopped) return;
      setState(tries === 0 ? "connecting" : "reconnecting");
      setNextRetryAt(null);
      const ws = new WebSocket(wsUrl(target));
      wsRef.current = ws;
      ws.onopen = () => {
        tries = 0;
        setAttempt(0);
        setState("open");
        setLastError(null);
      };
      ws.onmessage = (ev) => {
        try {
          const value = selectRef.current(JSON.parse(ev.data));
          if (value !== undefined) {
            setData(value);
            setReceivedAt(Date.now());
          }
        } catch {
          /* ignore malformed frames */
        }
      };
      ws.onclose = (ev) => {
        if (stopped) return;
        if (ev.code === 1008) setLastError(`Recusado pela API: ${ev.reason || "autenticação"}`);
        else setLastError("Conexão perdida com a API.");
        const base = BACKOFF_STEPS_MS[Math.min(tries, BACKOFF_STEPS_MS.length - 1)];
        const delay = base + Math.round(Math.random() * base * 0.2);
        tries += 1;
        setAttempt(tries);
        setState("reconnecting");
        setNextRetryAt(Date.now() + delay);
        timer = setTimeout(connect, delay);
      };
      ws.onerror = () => {
        /* onclose follows and schedules the retry */
      };
    };

    connect();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      wsRef.current?.close();
      setState("closed");
    };
  }, [path]);

  const send = useCallback((msg: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) wsRef.current.send(msg);
  }, []);

  return { data, receivedAt, state, attempt, nextRetryAt, lastError, send };
}
