"use client";

import React, { useRef, useEffect } from "react";
import { motion } from "framer-motion";
import { Terminal, Shield, Zap } from "lucide-react";

interface Finding {
    name: string;
    severity: string;
    url: string;
    evidence: string;
    param?: string;
    payload?: string;
    cwe?: string;
}

interface DualCombatTerminalsProps {
    findings: Finding[];
    isRunning?: boolean;
}

export function DualCombatTerminals({ findings, isRunning = true }: DualCombatTerminalsProps) {
    const redScrollRef = useRef<HTMLDivElement>(null);
    const blueScrollRef = useRef<HTMLDivElement>(null);

    // Filter CRITICAL, HIGH, and MEDIUM findings for Red and Blue terminals
    const combatFiltered = (findings || []).filter((f) => {
        const s = (f.severity || "").toLowerCase();
        return s === "critical" || s === "high" || s === "medium";
    });

    useEffect(() => {
        if (redScrollRef.current) {
            redScrollRef.current.scrollTop = redScrollRef.current.scrollHeight;
        }
        if (blueScrollRef.current) {
            blueScrollRef.current.scrollTop = blueScrollRef.current.scrollHeight;
        }
    }, [findings]);

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 w-full h-full min-h-0">
            {/* ── 1. RED TEAM OFFENSIVE TERMINAL (CRITICAL, HIGH & MEDIUM) ── */}
            <div className="rounded-xl overflow-hidden bg-[#120709]/95 border border-red-500/25 shadow-[0_0_20px_rgba(239,68,68,0.1)] flex flex-col h-full min-h-0">
                {/* Header Chrome */}
                <div className="flex items-center justify-between px-2.5 py-1 bg-[#1f0a0d]/90 border-b border-red-500/15 shrink-0">
                    <div className="flex items-center gap-2">
                        <div className="flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                            <span className="w-2 h-2 rounded-full bg-red-800" />
                            <span className="w-2 h-2 rounded-full bg-red-950" />
                        </div>
                        <span className="text-[11px] font-mono font-bold text-red-400 tracking-wide flex items-center gap-1">
                            <Zap className="w-3 h-3 text-red-500" />
                            RED TEAM • EXPLOIT STREAM
                        </span>
                    </div>
                    <span className="text-[9px] font-mono text-red-400/80 uppercase px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20">
                        {combatFiltered.length} Crit / High / Med
                    </span>
                </div>

                {/* Log View */}
                <div
                    ref={redScrollRef}
                    className="flex-1 p-2.5 overflow-y-auto space-y-1.5 text-[11px] font-mono glass-scrollbar"
                >
                    {combatFiltered.length === 0 ? (
                        <div className="text-red-400/40 italic flex flex-col gap-1 py-2">
                            <span>› Awaiting Critical, High & Medium attack vectors...</span>
                            <span className="text-[10px] text-red-500/30">Target parameters undergoing active probing</span>
                        </div>
                    ) : (
                        combatFiltered.map((finding, idx) => {
                            const sev = (finding.severity || "").toLowerCase();
                            const isCrit = sev === "critical";
                            const isHigh = sev === "high";
                            return (
                                <motion.div
                                    key={idx}
                                    initial={{ opacity: 0, x: -6 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ duration: 0.15 }}
                                    className="leading-relaxed border-l-2 pl-2 border-red-500/40 bg-red-950/10 py-0.5"
                                >
                                    <div className="flex items-center gap-1.5">
                                        <span className={`px-1 rounded text-[9px] font-bold ${
                                            isCrit
                                                ? "bg-red-500/30 text-red-300 border border-red-500/40"
                                                : isHigh
                                                ? "bg-orange-500/25 text-orange-300 border border-orange-500/40"
                                                : "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                                        }`}>
                                            {isCrit ? "CRIT" : isHigh ? "HIGH" : "MED"}
                                        </span>
                                        <span className="text-red-200 font-semibold truncate">{finding.name}</span>
                                    </div>
                                    <div className="text-[10px] text-red-400/70 truncate mt-0.5">
                                        target: <span className="text-white/60">{finding.url}</span>
                                    </div>
                                    {finding.param && (
                                        <div className="text-[10px] text-red-300/80 font-mono">
                                            payload: <code className="text-red-200 bg-red-950/40 px-1 rounded">{finding.payload || "probe_trigger"}</code>
                                        </div>
                                    )}
                                </motion.div>
                            );
                        })
                    )}
                </div>
            </div>

            {/* ── 2. BLUE TEAM SHIELD TERMINAL (DEFENSE & VIRTUAL PATCHING) ── */}
            <div className="rounded-xl overflow-hidden bg-[#06101c]/95 border border-cyan-500/25 shadow-[0_0_20px_rgba(6,182,212,0.1)] flex flex-col h-full min-h-0">
                {/* Header Chrome */}
                <div className="flex items-center justify-between px-2.5 py-1 bg-[#0a1b30]/90 border-b border-cyan-500/15 shrink-0">
                    <div className="flex items-center gap-2">
                        <div className="flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-cyan-400" />
                            <span className="w-2 h-2 rounded-full bg-blue-600" />
                            <span className="w-2 h-2 rounded-full bg-blue-950" />
                        </div>
                        <span className="text-[11px] font-mono font-bold text-cyan-300 tracking-wide flex items-center gap-1">
                            <Shield className="w-3 h-3 text-cyan-400" />
                            BLUE SHIELD • VIRTUAL DEFENSE
                        </span>
                    </div>
                    <span className="text-[9px] font-mono text-cyan-400/80 uppercase px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">
                        {combatFiltered.length} Patches Active
                    </span>
                </div>

                {/* Log View */}
                <div
                    ref={blueScrollRef}
                    className="flex-1 p-2.5 overflow-y-auto space-y-1.5 text-[11px] font-mono glass-scrollbar"
                >
                    {combatFiltered.length === 0 ? (
                        <div className="text-cyan-400/40 italic flex flex-col gap-1 py-2">
                            <span>› Autonomous Blue Shield armed and standing by...</span>
                            <span className="text-[10px] text-cyan-500/30">Micro-WAF inspection rules ready to synthesize</span>
                        </div>
                    ) : (
                        combatFiltered.map((finding, idx) => (
                            <motion.div
                                key={idx}
                                initial={{ opacity: 0, x: 6 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ duration: 0.15 }}
                                className="leading-relaxed border-l-2 pl-2 border-cyan-500/40 bg-cyan-950/10 py-0.5"
                            >
                                <div className="flex items-center gap-1.5">
                                    <span className="px-1 rounded text-[9px] font-bold bg-cyan-500/20 text-cyan-300">
                                        SHIELD V-PATCH
                                    </span>
                                    <span className="text-cyan-200 font-semibold truncate">
                                        Mitigated: {finding.name}
                                    </span>
                                </div>
                                <div className="text-[10px] text-cyan-400/70 truncate mt-0.5">
                                    rule: <span className="text-cyan-300 font-mono">SecRule ARGS "@rx {finding.param || 'exploit'}" -&gt; 403 DENY</span>
                                </div>
                                <div className="text-[10px] text-emerald-400/80 flex items-center gap-1">
                                    <span>✔ Perimeter Neutralized</span>
                                    <span className="text-white/40">• {finding.cwe || "CWE-Active"}</span>
                                </div>
                            </motion.div>
                        ))
                    )}
                </div>
            </div>
        </div>
    );
}
