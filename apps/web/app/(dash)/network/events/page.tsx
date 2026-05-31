"use client";

import { useState } from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api";
import { getToken } from "@/lib/auth";
import { useRealtimeEvents } from "@/lib/ws";
import { VulnSeverityBadge, eventKindLabel } from "@/components/network-state";
import type { NetworkEventItem } from "@/lib/types";

const KIND_FILTERS = [
  "all",
  "outbound_suspicious",
  "port_scan",
  "arp_spoof",
  "new_open_port",
  "new_device",
] as const;
type KindFilter = (typeof KIND_FILTERS)[number];
const KIND_FILTER_LABELS: Record<KindFilter, string> = {
  all: "Tous",
  outbound_suspicious: "Flux suspects",
  port_scan: "Scans de ports",
  arp_spoof: "ARP spoofing",
  new_open_port: "Nouveaux ports",
  new_device: "Nouveaux appareils",
};

export default function EventsPage() {
  const token = getToken() ?? "";
  const qc = useQueryClient();
  const [kind, setKind] = useState<KindFilter>("all");

  const url = kind === "all" ? "/network/events" : `/network/events?kind=${kind}`;

  const { data: events = [], isLoading } = useQuery<NetworkEventItem[]>({
    queryKey: ["network-events", kind],
    queryFn: () => apiFetch<NetworkEventItem[]>(url, token),
    refetchInterval: 20_000,
  });

  useRealtimeEvents(() => {
    qc.invalidateQueries({ queryKey: ["network-events"] });
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Link
            href="/network"
            className="text-sm text-slate-500 transition-colors hover:text-slate-700 dark:hover:text-slate-300"
          >
            ← Réseau
          </Link>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
            Intrusions & anomalies
          </h1>
        </div>
        <div className="flex flex-wrap gap-2">
          {KIND_FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setKind(f)}
              className={`rounded px-3 py-1 text-xs font-medium transition-colors ${
                kind === f
                  ? "bg-sky-600 text-white"
                  : "bg-slate-200 text-slate-600 hover:bg-slate-300 hover:text-slate-900 dark:bg-slate-800 dark:text-slate-400 dark:hover:bg-slate-700 dark:hover:text-slate-200"
              }`}
            >
              {KIND_FILTER_LABELS[f]}
            </button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <p className="text-sm text-slate-500">Chargement…</p>
      ) : events.length === 0 ? (
        <p className="text-sm text-slate-500">
          Aucun événement. Les intrusions apparaissent ici dès qu&apos;un agent en détecte
          (flux sortants suspects, scan de ports, ARP spoofing, nouveaux appareils/ports).
        </p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700/50">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-100 dark:border-slate-700/50 dark:bg-slate-800/60">
                {["Sévérité", "Type", "Message", "Source", "Destination", "Appareil", "Quand"].map(
                  (h) => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400">
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-700/30">
              {events.map((e) => (
                <tr key={e.id} className="bg-white hover:bg-slate-50 dark:bg-transparent dark:hover:bg-slate-800/30">
                  <td className="px-4 py-3"><VulnSeverityBadge severity={e.severity} /></td>
                  <td className="px-4 py-3 text-xs font-medium text-slate-700 dark:text-slate-300">
                    {eventKindLabel(e.kind)}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-600 dark:text-slate-400">{e.message}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-500">{e.src_ip ?? "—"}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-500">
                    {e.dst_ip ?? "—"}
                    {e.dst_port != null ? `:${e.dst_port}` : ""}
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {e.device_id != null ? (
                      <Link href={`/network/${e.device_id}`} className="text-sky-600 hover:underline dark:text-sky-400">
                        #{e.device_id}
                      </Link>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500">
                    {new Date(e.created_at).toLocaleString("fr-FR")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
