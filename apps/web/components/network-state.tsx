import type {
  DeviceRisk,
  DeviceStatus,
  NetworkState,
  VulnSeverity,
} from "@/lib/types";

// ── État global du réseau ────────────────────────────────────────────────────

type StateMeta = { label: string; badge: string; dot: string };

export const NETWORK_STATE_META: Record<NetworkState, StateMeta> = {
  sain: {
    label: "Sain",
    badge: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-300 border-emerald-500/30",
    dot: "bg-emerald-500",
  },
  surveille: {
    label: "Surveillé",
    badge: "bg-sky-500/15 text-sky-600 dark:text-sky-300 border-sky-500/30",
    dot: "bg-sky-500",
  },
  alarme: {
    label: "Alarme",
    badge: "bg-amber-500/15 text-amber-600 dark:text-amber-300 border-amber-500/30",
    dot: "bg-amber-500",
  },
  sature: {
    label: "Saturé",
    badge: "bg-orange-500/15 text-orange-600 dark:text-orange-300 border-orange-500/30",
    dot: "bg-orange-500",
  },
  critique: {
    label: "Critique",
    badge: "bg-rose-500/15 text-rose-600 dark:text-rose-300 border-rose-500/30",
    dot: "bg-rose-500",
  },
  indisponible: {
    label: "Indisponible",
    badge: "bg-slate-500/15 text-slate-500 dark:text-slate-400 border-slate-500/30",
    dot: "bg-slate-400",
  },
};

export function NetworkStateBadge({
  state,
  size = "md",
}: {
  state: NetworkState;
  size?: "md" | "lg";
}) {
  const meta = NETWORK_STATE_META[state];
  const sizing =
    size === "lg" ? "gap-2 px-4 py-1.5 text-sm" : "gap-1.5 px-2.5 py-0.5 text-xs";
  return (
    <span
      className={`inline-flex items-center rounded-full border font-medium ${sizing} ${meta.badge}`}
    >
      <span className={`h-2 w-2 rounded-full ${meta.dot}`} />
      {meta.label}
    </span>
  );
}

// ── Statut de connectivité d'un appareil ─────────────────────────────────────

const DEVICE_STATUS_META: Record<DeviceStatus, { label: string; cls: string }> = {
  up: { label: "Actif", cls: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-300 border-emerald-500/30" },
  down: { label: "Hors-ligne", cls: "bg-rose-500/15 text-rose-600 dark:text-rose-300 border-rose-500/30" },
  unknown: { label: "Inconnu", cls: "bg-slate-500/15 text-slate-500 dark:text-slate-400 border-slate-500/30" },
};

export function DeviceStatusBadge({ status }: { status: DeviceStatus }) {
  const meta = DEVICE_STATUS_META[status] ?? DEVICE_STATUS_META.unknown;
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs ${meta.cls}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {meta.label}
    </span>
  );
}

// ── Niveau de risque (Phase B : alimenté par les vulnérabilités) ─────────────

const DEVICE_RISK_META: Record<DeviceRisk, { label: string; cls: string }> = {
  safe: { label: "Sain", cls: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-300" },
  vulnerable: { label: "Vulnérable", cls: "bg-amber-500/15 text-amber-600 dark:text-amber-300" },
  critical: { label: "Critique", cls: "bg-rose-500/15 text-rose-600 dark:text-rose-300" },
};

export function DeviceRiskBadge({ risk }: { risk: DeviceRisk }) {
  const meta = DEVICE_RISK_META[risk] ?? DEVICE_RISK_META.safe;
  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${meta.cls}`}>
      {meta.label}
    </span>
  );
}

// ── Type d'appareil ──────────────────────────────────────────────────────────

// ── Sévérité d'une vulnérabilité ─────────────────────────────────────────────

const VULN_SEVERITY_META: Record<VulnSeverity, { label: string; cls: string }> = {
  critical: { label: "Critique", cls: "bg-rose-500/15 text-rose-600 dark:text-rose-300 border-rose-500/30" },
  high: { label: "Élevée", cls: "bg-orange-500/15 text-orange-600 dark:text-orange-300 border-orange-500/30" },
  medium: { label: "Moyenne", cls: "bg-amber-500/15 text-amber-600 dark:text-amber-300 border-amber-500/30" },
  low: { label: "Faible", cls: "bg-sky-500/15 text-sky-600 dark:text-sky-300 border-sky-500/30" },
  info: { label: "Info", cls: "bg-slate-500/15 text-slate-500 dark:text-slate-400 border-slate-500/30" },
};

export function VulnSeverityBadge({ severity }: { severity: VulnSeverity }) {
  const meta = VULN_SEVERITY_META[severity] ?? VULN_SEVERITY_META.info;
  return (
    <span
      className={`inline-block rounded-full border px-2 py-0.5 text-xs font-medium ${meta.cls}`}
    >
      {meta.label}
    </span>
  );
}

export const VULN_SEVERITY_RANK: Record<VulnSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export const DEVICE_TYPE_LABELS: Record<string, string> = {
  router: "Routeur",
  server: "Serveur",
  workstation: "Poste",
  printer: "Imprimante",
  phone: "Téléphone",
  iot: "IoT",
  nas: "NAS",
  unknown: "Inconnu",
};

export function deviceTypeLabel(type: string): string {
  return DEVICE_TYPE_LABELS[type] ?? type;
}

// ── Types d'événement d'intrusion ────────────────────────────────────────────

export const EVENT_KIND_LABELS: Record<string, string> = {
  new_device: "Nouvel appareil",
  new_open_port: "Nouveau port ouvert",
  port_scan: "Scan de ports",
  arp_spoof: "ARP spoofing",
  outbound_suspicious: "Flux sortant suspect",
  ids_alert: "Alerte IDS",
};

export function eventKindLabel(kind: string): string {
  return EVENT_KIND_LABELS[kind] ?? kind;
}
