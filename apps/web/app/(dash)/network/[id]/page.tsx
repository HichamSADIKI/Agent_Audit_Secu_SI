"use client";

import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api";
import { getToken } from "@/lib/auth";
import {
  DeviceStatusBadge,
  DeviceRiskBadge,
  VulnSeverityBadge,
  deviceTypeLabel,
} from "@/components/network-state";
import type { Device, DevicePort, DeviceStatus, Vuln } from "@/lib/types";

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700/50 dark:bg-slate-800/40 dark:shadow-none">
      <p className="text-xs text-slate-500 dark:text-slate-400">{label}</p>
      <p className={`mt-1 text-sm text-slate-900 dark:text-slate-100 ${mono ? "font-mono" : ""}`}>
        {value}
      </p>
    </div>
  );
}

export default function DevicePage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const token = getToken() ?? "";

  const { data: device, isLoading } = useQuery<Device>({
    queryKey: ["device", id],
    queryFn: () => apiFetch<Device>(`/network/devices/${id}`, token),
    refetchInterval: 30_000,
  });

  const { data: ports = [] } = useQuery<DevicePort[]>({
    queryKey: ["device-ports", id],
    queryFn: () => apiFetch<DevicePort[]>(`/network/devices/${id}/ports`, token),
    refetchInterval: 30_000,
  });

  const { data: vulns = [] } = useQuery<Vuln[]>({
    queryKey: ["device-vulns", id],
    queryFn: () => apiFetch<Vuln[]>(`/network/devices/${id}/vulns`, token),
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3">
        <button
          onClick={() => router.push("/network")}
          className="text-sm text-slate-500 transition-colors hover:text-slate-700 dark:hover:text-slate-300"
        >
          ← Retour
        </button>
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
          {device?.hostname ?? device?.ip ?? "…"}
        </h1>
        {device && <DeviceStatusBadge status={device.status as DeviceStatus} />}
        {device && <DeviceRiskBadge risk={device.risk} />}
        {device?.is_gateway && (
          <span className="rounded bg-sky-500/15 px-2 py-0.5 text-xs text-sky-600 dark:text-sky-300">
            passerelle
          </span>
        )}
      </div>

      {isLoading || !device ? (
        <p className="text-sm text-slate-500">Chargement…</p>
      ) : (
        <>
          {/* Identité */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Field label="Adresse IP" value={device.ip} mono />
            <Field label="Adresse MAC" value={device.mac ?? "—"} mono />
            <Field label="Nom d'hôte" value={device.hostname ?? "—"} />
            <Field label="Type" value={deviceTypeLabel(device.device_type)} />
            <Field label="Système (estimé)" value={device.os_guess ?? "—"} />
            <Field label="Constructeur" value={device.vendor ?? "—"} />
            <Field label="Découvert par (agent)" value={`#${device.discovered_by_machine_id}`} />
            <Field
              label="Première détection"
              value={new Date(device.first_seen_at).toLocaleString("fr-FR")}
            />
            <Field
              label="Dernière détection"
              value={new Date(device.last_seen_at).toLocaleString("fr-FR")}
            />
          </div>

          {/* Vulnérabilités */}
          <section className="space-y-3">
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">
              Vulnérabilités{" "}
              <span className="text-slate-400">({vulns.length})</span>
            </h2>
            {vulns.length === 0 ? (
              <p className="text-sm text-slate-500">Aucune vulnérabilité détectée.</p>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700/50">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-100 dark:border-slate-700/50 dark:bg-slate-800/60">
                      {["Sévérité", "CVE", "Titre", "CVSS", "Port", "Source"].map((h) => (
                        <th key={h} className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-700/30">
                    {vulns.map((v) => (
                      <tr key={v.id} className="bg-white hover:bg-slate-50 dark:bg-transparent dark:hover:bg-slate-800/30">
                        <td className="px-4 py-3"><VulnSeverityBadge severity={v.severity} /></td>
                        <td className="px-4 py-3 font-mono text-xs text-slate-600 dark:text-slate-400">
                          {v.cve_id ?? "—"}
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-700 dark:text-slate-300">
                          <div>{v.title}</div>
                          {v.description && (
                            <div className="mt-0.5 text-slate-400">{v.description}</div>
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-500">{v.cvss ?? "—"}</td>
                        <td className="px-4 py-3 font-mono text-xs text-slate-500">
                          {ports.find((p) => p.id === v.port_id)?.port ?? "—"}
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-400">
                          {v.source === "cve-db" ? "Base CVE" : "Règle"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {/* Ports ouverts */}
          <section className="space-y-3">
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">
              Ports ouverts <span className="text-slate-400">({ports.length})</span>
            </h2>
            {ports.length === 0 ? (
              <p className="text-sm text-slate-500">Aucun port ouvert détecté.</p>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700/50">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-100 dark:border-slate-700/50 dark:bg-slate-800/60">
                      {["Port", "Proto", "Service", "Version", "Bannière"].map((h) => (
                        <th key={h} className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-700/30">
                    {ports.map((p) => (
                      <tr key={p.id} className="bg-white hover:bg-slate-50 dark:bg-transparent dark:hover:bg-slate-800/30">
                        <td className="px-4 py-3 font-mono text-xs text-slate-700 dark:text-slate-300">{p.port}</td>
                        <td className="px-4 py-3 text-xs text-slate-500">{p.protocol}</td>
                        <td className="px-4 py-3 text-xs text-slate-600 dark:text-slate-400">{p.service_name ?? "—"}</td>
                        <td className="px-4 py-3 text-xs text-slate-500">{p.service_version ?? "—"}</td>
                        <td className="max-w-md truncate px-4 py-3 font-mono text-[11px] text-slate-400">
                          {p.banner ?? "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
