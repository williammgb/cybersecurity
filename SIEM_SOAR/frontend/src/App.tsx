import { useEffect, useMemo, useState } from "react";
import type { ChangeEvent } from "react";
import {
  AppBar,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Container,
  createTheme,
  FormControl,
  Grid,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  type SelectChangeEvent,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TableContainer,
  TextField,
  ThemeProvider,
  Toolbar,
  Typography,
} from "@mui/material";

type GenericRow = Record<string, unknown>;

const API_BASE = "http://localhost:8001";

const dashboardTheme = createTheme({
  palette: {
    mode: "dark",
    primary: { main: "#58a6ff" },
    background: { default: "#0d1117", paper: "#161b22" },
  },
  typography: {
    fontFamily: '"Segoe UI", system-ui, sans-serif',
  },
  components: {
    MuiPaper: { styleOverrides: { root: { backgroundImage: "none" } } },
  },
});

async function getJson(path: string) {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(`Failed request: ${path}`);
  }
  return response.json();
}

function formatTimestamp(value: unknown): string {
  if (typeof value !== "string" || !value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

function toDateMs(value: unknown): number {
  if (typeof value !== "string") return 0;
  const ms = new Date(value).getTime();
  return Number.isNaN(ms) ? 0 : ms;
}

function parseSnapshot(snapshot: unknown): GenericRow | null {
  if (typeof snapshot !== "string" || !snapshot.trim()) return null;
  try {
    const parsed = JSON.parse(snapshot) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as GenericRow;
    }
  } catch {
    /* ignore parse errors */
  }
  return null;
}

/** Show '-' for empty, 'none', or 'no_signal' so the UI does not look like a fault state. */
function displayCell(value: unknown): string {
  const s = String(value ?? "").trim();
  const lower = s.toLowerCase();
  if (!s || lower === "none" || lower === "no_signal") return "-";
  return s;
}

/** IPs whose latest block row is still `block`. */
function activeBlockedIps(rows: GenericRow[]): string[] {
  const latestByIp = new Map<string, GenericRow>();
  for (const row of rows) {
    const ip = String(row.source_ip || "");
    if (!ip) continue;
    const id = Number(row.id);
    const prev = latestByIp.get(ip);
    if (!prev || id > Number(prev.id)) {
      latestByIp.set(ip, row);
    }
  }
  return [...latestByIp.entries()]
    .filter(([, row]) => String(row.action) === "block")
    .map(([ip]) => ip)
    .sort();
}

function formatPayloadDisplay(raw: unknown) {
  const s = String(raw ?? "");
  try {
    const parsed = JSON.parse(s) as unknown;
    if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
      const obj = parsed as Record<string, unknown>;
      return (
        <Stack component="div" spacing={0.75}>
          {Object.entries(obj).map(([k, v]) => (
            <Typography
              key={k}
              variant="caption"
              component="div"
              sx={{ wordBreak: "break-word", lineHeight: 1.5, color: "#e6edf3" }}
            >
              <strong>{k}:</strong>{" "}
              {v !== null && typeof v === "object" ? JSON.stringify(v) : String(v)}
            </Typography>
          ))}
        </Stack>
      );
    }
  } catch {
    /* not JSON */
  }
  return (
    <Typography variant="caption" component="div" sx={{ whiteSpace: "pre-wrap", wordBreak: "break-word", color: "#e6edf3" }}>
      {s}
    </Typography>
  );
}

type TrafficPace = "slow" | "normal" | "fast";

function AppContent() {
  const [summary, setSummary] = useState<GenericRow>({});
  const [events, setEvents] = useState<GenericRow[]>([]);
  const [detections, setDetections] = useState<GenericRow[]>([]);
  const [blocks, setBlocks] = useState<GenericRow[]>([]);
  const [selectedDetectionId, setSelectedDetectionId] = useState<number | null>(null);
  const [filter, setFilter] = useState("");
  const [unblockPick, setUnblockPick] = useState("");
  const [networkPaused, setNetworkPaused] = useState(false);
  const [trafficPace, setTrafficPace] = useState<TrafficPace>("normal");
  const [selectedRelatedEvent, setSelectedRelatedEvent] = useState<GenericRow | null>(null);

  const blockedIpsList = useMemo(() => activeBlockedIps(blocks), [blocks]);

  const selectedDetection = useMemo(() => {
    if (selectedDetectionId == null) return null;
    return detections.find((d) => Number(d.id) === selectedDetectionId) ?? null;
  }, [detections, selectedDetectionId]);

  useEffect(() => {
    if (!selectedDetection) {
      setSelectedRelatedEvent(null);
      return;
    }
    const fallback = parseSnapshot(selectedDetection.related_event_snapshot);
    const detectionId = Number(selectedDetection.id);
    if (!Number.isFinite(detectionId) || detectionId <= 0) {
      setSelectedRelatedEvent(fallback);
      return;
    }
    getJson(`/api/detections/${detectionId}/related`)
      .then((res) => {
        const item = (res?.item as GenericRow | null) ?? null;
        setSelectedRelatedEvent(item ?? fallback);
      })
      .catch(() => setSelectedRelatedEvent(fallback));
  }, [selectedDetection]);

  const loadControlStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/control/status`);
      const j = await res.json();
      if (res.ok && typeof j.paused === "boolean") {
        setNetworkPaused(j.paused);
      }
    } catch {
      setNetworkPaused(false);
    }
  };

  const loadTrafficPace = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/simulation/traffic-pace`);
      if (!res.ok) return;
      const j = await res.json();
      const p = String(j.pace || "normal");
      if (p === "slow" || p === "normal" || p === "fast") {
        setTrafficPace(p);
      }
    } catch {
      /* ignore */
    }
  };

  const reload = async () => {
    const [s, e, d, b] = await Promise.all([
      getJson("/api/metrics/summary"),
      getJson("/api/events?limit=100"),
      getJson("/api/detections?limit=100"),
      getJson("/api/blocks?limit=100"),
    ]);
    const sortedEvents = [...(e.items || [])].sort((a, b) => toDateMs(b.timestamp) - toDateMs(a.timestamp));
    const sortedDetections = [...(d.items || [])].sort((a, b) => toDateMs(b.timestamp) - toDateMs(a.timestamp));
    const sortedBlocks = [...(b.items || [])].sort((a, b) => toDateMs(b.timestamp) - toDateMs(a.timestamp));
    setSummary(s);
    setEvents(sortedEvents);
    setDetections(sortedDetections);
    setBlocks(sortedBlocks);
  };

  const resetDashboard = async () => {
    if (!window.confirm("Clear all events, detections, blocks, and reset detector state?")) return;
    await fetch(`${API_BASE}/api/reset`, { method: "POST" });
    setSelectedDetectionId(null);
    setUnblockPick("");
    await reload();
    await loadControlStatus();
    await loadTrafficPace();
  };

  const toggleNetworkPause = async () => {
    const path = networkPaused ? "/api/control/resume" : "/api/control/pause";
    await fetch(`${API_BASE}${path}`, { method: "POST" });
    await loadControlStatus();
  };

  const onTrafficPaceChange = async (e: SelectChangeEvent<TrafficPace>) => {
    const pace = e.target.value as TrafficPace;
    setTrafficPace(pace);
    try {
      await fetch(`${API_BASE}/api/simulation/traffic-pace`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pace }),
      });
    } catch (err) {
      console.error(err);
    }
  };

  const unblockSelected = async () => {
    if (!unblockPick.trim()) return;
    const ip = encodeURIComponent(unblockPick.trim());
    await fetch(`${API_BASE}/api/blocks/${ip}/unblock`, { method: "POST" });
    setUnblockPick("");
    await reload();
  };

  useEffect(() => {
    reload().catch(console.error);
    loadControlStatus().catch(console.error);
    loadTrafficPace().catch(console.error);
    const ws = new WebSocket("ws://localhost:8001/api/stream/events");
    ws.onmessage = () => reload().catch(console.error);
    const timer = setInterval(() => {
      reload().catch(console.error);
      loadControlStatus().catch(console.error);
      loadTrafficPace().catch(console.error);
    }, 5000);
    return () => {
      ws.close();
      clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    if (unblockPick && !blockedIpsList.includes(unblockPick)) {
      setUnblockPick("");
    }
  }, [blockedIpsList, unblockPick]);

  const filteredEvents = useMemo(() => {
    const needle = filter.toLowerCase().trim();
    if (!needle) {
      return events;
    }
    return events.filter((item: GenericRow) => JSON.stringify(item).toLowerCase().includes(needle));
  }, [events, filter]);

  const relatedEvent = useMemo(() => {
    return selectedRelatedEvent;
  }, [selectedRelatedEvent]);

  const rpmSeries = useMemo(() => {
    const now = Date.now();
    const minuteMs = 60_000;
    const bins: { label: string; value: number; ts: number }[] = [];
    for (let i = 14; i >= 0; i -= 1) {
      const bucketTs = now - i * minuteMs;
      const d = new Date(bucketTs);
      const label = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
      bins.push({ label, value: 0, ts: bucketTs });
    }
    for (const ev of events) {
      const ts = toDateMs(ev.timestamp);
      if (!ts) continue;
      const diff = now - ts;
      if (diff < 0 || diff > 15 * minuteMs) continue;
      const index = 14 - Math.floor(diff / minuteMs);
      if (index >= 0 && index < bins.length) bins[index].value += 1;
    }
    return bins;
  }, [events]);

  const metricCards = [
    { label: "Total events", value: summary.total_events ?? 0 },
    { label: "Detections", value: summary.total_detections ?? 0 },
    { label: "Active blocks", value: summary.active_blocks ?? 0 },
    { label: "Blocked events", value: summary.blocked_events ?? 0 },
  ];

  const decisionChipColor = (decision: unknown) => {
    const d = String(decision || "");
    if (d === "blocked" || d === "suspicious") return "error" as const;
    if (d === "allowed_ip") return "info" as const;
    return "success" as const;
  };

  return (
    <Box sx={{ bgcolor: "background.default", minHeight: "100vh", color: "text.primary" }}>
      <AppBar position="static" elevation={0} sx={{ bgcolor: "#161b22", borderBottom: "1px solid", borderColor: "divider" }}>
        <Toolbar sx={{ flexWrap: "wrap", gap: 1, py: 1 }}>
          <Typography variant="h6" component="div" sx={{ fontWeight: 600, mr: 1 }}>
            SIEM / SOAR Dashboard
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ flex: 1, alignItems: "stretch", minWidth: 0 }}>
            {metricCards.map((card) => (
              <Paper
                key={card.label}
                variant="outlined"
                sx={{
                  px: 1.25,
                  py: 0.5,
                  minWidth: 100,
                  borderColor: "divider",
                  bgcolor: "background.paper",
                }}
              >
                <Typography variant="caption" color="text.secondary" display="block" sx={{ lineHeight: 1.2 }}>
                  {card.label}
                </Typography>
                <Typography variant="body2" fontWeight={700}>
                  {String(card.value)}
                </Typography>
              </Paper>
            ))}
          </Stack>
        </Toolbar>
      </AppBar>

      <Container sx={{ py: 2 }} maxWidth="xl">
        <Stack direction={{ xs: "column", lg: "row" }} spacing={2} sx={{ mb: 2 }} alignItems={{ lg: "center" }} flexWrap="wrap">
          <TextField
            value={filter}
            onChange={(e: ChangeEvent<HTMLInputElement>) => setFilter(e.target.value)}
            label="Filter events"
            variant="outlined"
            size="small"
            sx={{ flex: 1, minWidth: 200 }}
          />
          <FormControl size="small" sx={{ minWidth: 170 }}>
            <InputLabel id="traffic-pace-label">Traffic pace</InputLabel>
            <Select<TrafficPace>
              labelId="traffic-pace-label"
              value={trafficPace}
              label="Traffic pace"
              onChange={onTrafficPaceChange}
            >
              <MenuItem value="slow">Slow</MenuItem>
              <MenuItem value="normal">Normal</MenuItem>
              <MenuItem value="fast">Fast</MenuItem>
            </Select>
          </FormControl>
          <Button variant="contained" size="small" onClick={() => reload().catch(console.error)}>
            Refresh
          </Button>
          <Button variant="contained" color="warning" size="small" onClick={() => resetDashboard().catch(console.error)}>
            Reset dashboard
          </Button>
          <Button
            variant="contained"
            color={networkPaused ? "success" : "secondary"}
            size="small"
            onClick={() => toggleNetworkPause().catch(console.error)}
          >
            {networkPaused ? "Resume network" : "Pause network"}
          </Button>
          <Chip label={networkPaused ? "Traffic paused" : "Traffic running"} color={networkPaused ? "warning" : "default"} variant="outlined" size="small" />
        </Stack>

        <Card sx={{ mb: 2 }} variant="outlined">
          <CardContent sx={{ pt: 2, "&:last-child": { pb: 2 } }}>
            <Typography variant="subtitle1" sx={{ mb: 1.5, fontWeight: 600 }}>
              Server timeline (requests per minute)
            </Typography>
            <Paper variant="outlined" sx={{ p: 1.5, mb: 2, bgcolor: "#0d1117", borderColor: "divider" }}>
              <Box sx={{ width: "100%", height: 180 }}>
                <svg width="100%" height="100%" viewBox="0 0 900 180" preserveAspectRatio="none">
                  <line x1="35" y1="150" x2="880" y2="150" stroke="#30363d" strokeWidth="1" />
                  <line x1="35" y1="20" x2="35" y2="150" stroke="#30363d" strokeWidth="1" />
                  {rpmSeries.length > 1 ? (
                    <>
                      <polyline
                        fill="none"
                        stroke="#58a6ff"
                        strokeWidth="2.5"
                        points={rpmSeries
                          .map((p, i) => {
                            const max = Math.max(1, ...rpmSeries.map((x) => x.value));
                            const x = 35 + (i / (rpmSeries.length - 1)) * 845;
                            const y = 150 - (p.value / max) * 120;
                            return `${x},${y}`;
                          })
                          .join(" ")}
                      />
                      {rpmSeries.map((p, i) => {
                        const max = Math.max(1, ...rpmSeries.map((x) => x.value));
                        const x = 35 + (i / (rpmSeries.length - 1)) * 845;
                        const y = 150 - (p.value / max) * 120;
                        return <circle key={`${p.label}-${i}`} cx={x} cy={y} r="2.5" fill="#79c0ff" />;
                      })}
                    </>
                  ) : null}
                </svg>
              </Box>
            </Paper>
            <Typography variant="subtitle1" sx={{ mb: 1.5, fontWeight: 600 }}>
              Live events
            </Typography>
            <TableContainer sx={{ maxHeight: 520 }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell>Event ID</TableCell>
                  <TableCell>Time</TableCell>
                  <TableCell>Country</TableCell>
                  <TableCell>Source IP</TableCell>
                  <TableCell>Actor</TableCell>
                  <TableCell>Signal</TableCell>
                  <TableCell>Decision</TableCell>
                  <TableCell>Reason</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredEvents.slice(0, 50).map((event: GenericRow, index: number) => (
                  <TableRow key={String(event.event_id ?? index)} hover>
                    <TableCell sx={{ wordBreak: "break-all", maxWidth: 220 }}>{displayCell(event.event_id)}</TableCell>
                    <TableCell>{formatTimestamp(event.timestamp)}</TableCell>
                    <TableCell>{displayCell(event.country)}</TableCell>
                    <TableCell>{String(event.source_ip || "")}</TableCell>
                    <TableCell>{String(event.actor_type || "")}</TableCell>
                    <TableCell>{displayCell(event.signal_type)}</TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={displayCell(event.decision)}
                        color={decisionChipColor(event.decision)}
                        variant={event.decision === "blocked" || event.decision === "suspicious" ? "filled" : "outlined"}
                      />
                    </TableCell>
                    <TableCell>{displayCell(event.reason)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </TableContainer>
          </CardContent>
        </Card>

        <Card sx={{ mb: 2 }} variant="outlined">
          <CardContent sx={{ pt: 2, "&:last-child": { pb: 2 } }}>
            <Typography variant="subtitle1" sx={{ mb: 2, fontWeight: 600 }}>
              Detections
            </Typography>
            <Grid container spacing={2} wrap="nowrap" sx={{ flexDirection: { xs: "column", md: "row" } }}>
              <Grid item xs={12} md={6} sx={{ minWidth: 0, flex: { md: "1 1 50%" } }}>
                <TableContainer sx={{ maxHeight: 520 }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell>Time</TableCell>
                      <TableCell>Source IP</TableCell>
                      <TableCell>Signal</TableCell>
                      <TableCell>Note</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {detections.slice(0, 15).map((detection: GenericRow) => {
                      const id = Number(detection.id);
                      return (
                        <TableRow
                          key={id}
                          hover
                          selected={selectedDetectionId === id}
                          sx={{ cursor: "pointer" }}
                          onClick={() => setSelectedDetectionId(id)}
                        >
                          <TableCell>{formatTimestamp(detection.timestamp)}</TableCell>
                          <TableCell>{String(detection.source_ip || "")}</TableCell>
                          <TableCell>{displayCell(detection.signal_type)}</TableCell>
                          <TableCell>{String(detection.note || "")}</TableCell>
                        </TableRow>
                      );
                    })}
                    {detections.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={4}>
                          <Typography variant="body2" color="text.secondary">
                            No detections yet. They will appear when suspicious or blocked signals are triggered.
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ) : null}
                  </TableBody>
                </Table>
                </TableContainer>
              </Grid>
              <Grid item xs={12} md={6} sx={{ minWidth: 0, flex: { md: "1 1 50%" }, maxWidth: { md: "50%" } }}>
                <Paper
                  variant="outlined"
                  sx={{
                    p: 2,
                    minHeight: 280,
                    height: "100%",
                    bgcolor: "background.paper",
                    display: "flex",
                    flexDirection: "column",
                    overflow: "hidden",
                  }}
                >
                  <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600 }}>
                    Detection information
                  </Typography>
                  {!selectedDetection ? (
                    <Typography variant="body2" color="text.secondary">
                      Select a detection in the table to view metadata and the related event.
                    </Typography>
                  ) : (
                    <Stack spacing={2} sx={{ minHeight: 0, flex: 1, overflow: "hidden" }}>
                      <Box sx={{ flexShrink: 0 }}>
                        <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.5 }}>
                          Detection metadata
                        </Typography>
                        <Typography variant="body2">ID: {String(selectedDetection.id ?? "")}</Typography>
                        <Typography variant="body2">Signal: {displayCell(selectedDetection.signal_type)}</Typography>
                        <Typography variant="body2">Note: {String(selectedDetection.note || "")}</Typography>
                        {relatedEvent ? (
                          <Box sx={{ mt: 1.5 }}>
                            <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.5 }}>
                              Session
                            </Typography>
                            <Typography variant="body2">Country: {displayCell(relatedEvent.country)}</Typography>
                            <Typography variant="body2">City: {displayCell(relatedEvent.city)}</Typography>
                            <Typography variant="body2">ISP: {displayCell(relatedEvent.isp)}</Typography>
                            <Typography variant="body2">Device type: {displayCell(relatedEvent.device_type)}</Typography>
                          </Box>
                        ) : null}
                      </Box>
                      <Box sx={{ minHeight: 0, flex: 1, display: "flex", flexDirection: "column" }}>
                        <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.5 }}>
                          Related event
                        </Typography>
                        {relatedEvent ? (
                          <>
                            <Typography variant="body2">Event ID: {displayCell(relatedEvent.event_id)}</Typography>
                            <Typography variant="body2">Actor: {String(relatedEvent.actor_type || "")}</Typography>
                            <Typography variant="body2">Decision: {displayCell(relatedEvent.decision)}</Typography>
                            <Typography variant="body2">Reason: {displayCell(relatedEvent.reason)}</Typography>
                            <Typography variant="body2">Method: {String(relatedEvent.method || "")}</Typography>
                            <Typography variant="body2">Endpoint: {String(relatedEvent.endpoint || "")}</Typography>
                            <Typography variant="body2" sx={{ mt: 1 }}>
                              Payload
                            </Typography>
                            <Paper
                              variant="outlined"
                              sx={{
                                p: 1,
                                flex: 1,
                                minHeight: 120,
                                maxHeight: 220,
                                overflow: "auto",
                                bgcolor: "#0d1117",
                                borderColor: "divider",
                              }}
                            >
                              {formatPayloadDisplay(relatedEvent.payload)}
                            </Paper>
                          </>
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            No related event available.
                          </Typography>
                        )}
                      </Box>
                    </Stack>
                  )}
                </Paper>
              </Grid>
            </Grid>
          </CardContent>
        </Card>

        <Card variant="outlined">
          <CardContent sx={{ pt: 2, "&:last-child": { pb: 2 } }}>
            <Typography variant="subtitle1" sx={{ mb: 1, fontWeight: 600 }}>
              Blocked IPs
            </Typography>
            <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>
              Block and unblock actions (latest entries first)
            </Typography>
            <Table size="small" sx={{ mb: 2, tableLayout: "fixed" }}>
              <TableHead>
                <TableRow>
                  <TableCell width="22%">Time</TableCell>
                  <TableCell width="18%">Source IP</TableCell>
                  <TableCell width="14%">Action</TableCell>
                  <TableCell>Reason</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {blocks.slice(0, 20).map((block: GenericRow, index: number) => (
                  <TableRow key={index}>
                    <TableCell sx={{ wordBreak: "break-word" }}>{formatTimestamp(block.timestamp)}</TableCell>
                    <TableCell sx={{ wordBreak: "break-all" }}>{String(block.source_ip || "")}</TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={String(block.action || "")}
                        color={block.action === "block" ? "error" : "info"}
                        variant="filled"
                      />
                    </TableCell>
                    <TableCell sx={{ wordBreak: "break-word" }}>{String(block.reason || "")}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems={{ sm: "center" }}>
              <FormControl sx={{ minWidth: 220 }} size="small">
                <InputLabel id="unblock-ip-label">Blocked IP</InputLabel>
                <Select
                  labelId="unblock-ip-label"
                  value={blockedIpsList.includes(unblockPick) ? unblockPick : ""}
                  label="Blocked IP"
                  onChange={(e: SelectChangeEvent<string>) => setUnblockPick(e.target.value)}
                  displayEmpty
                >
                  {blockedIpsList.length === 0 ? (
                    <MenuItem value="" disabled>
                      No active blocks
                    </MenuItem>
                  ) : (
                    blockedIpsList.map((ip) => (
                      <MenuItem key={ip} value={ip}>
                        {ip}
                      </MenuItem>
                    ))
                  )}
                </Select>
              </FormControl>
              <Button variant="outlined" disabled={!unblockPick} onClick={() => unblockSelected().catch(console.error)}>
                Unblock selected IP
              </Button>
            </Stack>
          </CardContent>
        </Card>
      </Container>
    </Box>
  );
}

export default function App() {
  return (
    <ThemeProvider theme={dashboardTheme}>
      <AppContent />
    </ThemeProvider>
  );
}
