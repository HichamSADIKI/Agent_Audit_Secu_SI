"use client";

import { useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api";
import { getToken } from "@/lib/auth";
import { VulnSeverityBadge } from "@/components/network-state";
import type { Vuln, VulnSeverity } from "@/lib/types";

const FILTERS = ["all", "critical", "high", "medium", "low"] as const;
type Filter = (typeof FILTERS)[number];
const FILTER_LABELS: Record<Filter, string> = {
  all: "Toutes",
  critical: "Critiques",
  high: "Élevées",
  medium: "Moyennes",
  low: "Faibles",
};

export default function VulnsPage() {
  const token = getToken() ?? "";
  const [filter, setFilter] = useState<Filter>("all");

  const url = filter === "all" ? "/network/vulns" : `/network/vulns?severity=${filter}`;

  const { data: vulns = [], isLoading } = useQuery<Vuln[]>({
    queryKey: ["vulns", filter],
    queryFn: () => apiFetch<Vuln[]>(url, token),
    refetchInterval: 30_000,
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
            Vulnérabilités
          </h1>
        </div>
        <div className="flex flex-wrap gap-2">
          {FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`rounded px-3 py-1 text-xs font-medium transition-colors ${
                filter === f
                  ? "bg-sky-600 text-white"
                  : "bg-slate-200 text-slate-600 hover:bg-slate-300 hover:text-slate-900 dark:bg-slate-800 dark:text-slate-400 dark:hover:bg-slate-700 dark:hover:text-slate-200"
              }`}
            >
              {FILTER_LABELS[f]}
            </button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <p className="text-sm text-slate-500">Chargement…</p>
      ) : vulns.length === 0 ? (
        <p className="text-sm text-slate-500">Aucune vulnérabilité.</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700/50">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-100 dark:border-slate-700/50 dark:bg-slate-800/60">
                {["Sévérité", "Appareil", "CVE", "Titre", "CVSS", "Source"].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-700/30">
              {vulns.map((v) => (
                <tr key={v.id} className="bg-white hover:bg-slate-50 dark:bg-transparent dark:hover:bg-slate-800/30">
                  <td className="px-4 py-3"><VulnSeverityBadge severity={v.severity as VulnSeverity} /></td>
                  <td className="px-4 py-3 text-xs">
                    <Link
                      href={`/network/${v.device_id}`}
                      className="text-sky-600 hover:underline dark:text-sky-400"
                    >
                      {v.device_hostname ?? v.device_ip ?? `#${v.device_id}`}
                    </Link>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-600 dark:text-slate-400">{v.cve_id ?? "—"}</td>
                  <td className="px-4 py-3 text-xs text-slate-700 dark:text-slate-300">
                    <div>{v.title}</div>
                    {v.description && <div className="mt-0.5 text-slate-400">{v.description}</div>}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500">{v.cvss ?? "—"}</td>
                  <td className="px-4 py-3 text-xs text-slate-400">
                    {v.source === "cve-db" ? "Base CVE" : "Règle"}
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
