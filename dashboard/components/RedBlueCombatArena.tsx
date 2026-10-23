"use client";

import React from "react";

interface RedBlueCombatArenaProps {
    isComplete: boolean;
}

export function RedBlueCombatArena({ isComplete }: RedBlueCombatArenaProps) {
    return (
        <div className="flex items-center justify-center select-none pointer-events-none">
            {/* Pure Floating Cyber HUD Radar — No Box / No Background / No Borders */}
            <div className="w-36 md:w-44 h-10 md:h-12 flex items-center justify-center">
                {!isComplete ? (
                    /* ── 1. ACTIVE CYBER COMBAT: RED CROSSHAIR VS BLUE HEX SHIELD ── */
                    <svg
                        xmlns="http://www.w3.org/2000/svg"
                        viewBox="0 0 240 70"
                        className="w-full h-full"
                        preserveAspectRatio="xMidYMid meet"
                    >
                        <style>{`
                            .spin-slow {
                                transform-origin: 40px 35px;
                                animation: spinHud 6s linear infinite;
                                will-change: transform;
                            }
                            .pulse-red {
                                transform-origin: 40px 35px;
                                animation: pulseRedCore 1.6s ease-in-out infinite alternate;
                                will-change: transform, opacity;
                            }
                            .shield-ring {
                                transform-origin: 200px 35px;
                                animation: spinCounter 4s linear infinite;
                                will-change: transform;
                            }
                            .spark-node {
                                transform-origin: 120px 35px;
                                animation: energyPulse 1.2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
                                will-change: transform, opacity;
                            }
                            .spark-beam {
                                animation: beamFlash 1.2s ease-in-out infinite alternate;
                            }

                            @keyframes spinHud {
                                from { transform: rotate(0deg); }
                                to { transform: rotate(360deg); }
                            }
                            @keyframes spinCounter {
                                from { transform: rotate(360deg); }
                                to { transform: rotate(0deg); }
                            }
                            @keyframes pulseRedCore {
                                0% { transform: scale(0.92); opacity: 0.75; }
                                100% { transform: scale(1.08); opacity: 1; }
                            }
                            @keyframes energyPulse {
                                0%, 100% { transform: scale(0.8); opacity: 0.4; }
                                50% { transform: scale(1.3); opacity: 1; }
                            }
                            @keyframes beamFlash {
                                0% { stroke-dashoffset: 20; opacity: 0.3; }
                                100% { stroke-dashoffset: 0; opacity: 0.9; }
                            }
                        `}</style>

                        {/* Connection Energy Beam */}
                        <line
                            x1="60"
                            y1="35"
                            x2="180"
                            y2="35"
                            stroke="#ef4444"
                            strokeWidth="1.5"
                            strokeDasharray="4 3"
                            className="spark-beam"
                        />
                        <line
                            x1="120"
                            y1="35"
                            x2="180"
                            y2="35"
                            stroke="#06b6d4"
                            strokeWidth="1.5"
                            strokeDasharray="4 3"
                            className="spark-beam"
                        />

                        {/* Central Clash Deflection Node */}
                        <g className="spark-node">
                            <circle cx="120" cy="35" r="7" fill="none" stroke="#f59e0b" strokeWidth="1.5" />
                            <circle cx="120" cy="35" r="3.5" fill="#ffffff" />
                            <circle cx="120" cy="35" r="1.5" fill="#f59e0b" />
                        </g>

                        {/* ── LEFT: RED TEAM OFFENSIVE CROSSHAIR ── */}
                        <g>
                            {/* Rotating HUD Arc */}
                            <circle
                                cx="40"
                                cy="35"
                                r="18"
                                fill="none"
                                stroke="#dc2626"
                                strokeWidth="1.5"
                                strokeDasharray="18 10 8 10"
                                className="spin-slow"
                            />
                            {/* Target Crosshairs */}
                            <line x1="26" y1="35" x2="54" y2="35" stroke="#ef4444" strokeWidth="1.2" opacity="0.8" />
                            <line x1="40" y1="21" x2="40" y2="49" stroke="#ef4444" strokeWidth="1.2" opacity="0.8" />

                            {/* Core Laser Dot */}
                            <g className="pulse-red">
                                <circle cx="40" cy="35" r="5" fill="#ef4444" opacity="0.3" />
                                <circle cx="40" cy="35" r="2.5" fill="#ef4444" />
                            </g>
                        </g>

                        {/* ── RIGHT: BLUE SHIELD FORTRESS ── */}
                        <g>
                            {/* Rotating Defense Outer Ring */}
                            <circle
                                cx="200"
                                cy="35"
                                r="19"
                                fill="none"
                                stroke="#06b6d4"
                                strokeWidth="1.5"
                                strokeDasharray="12 8 20 8"
                                className="shield-ring"
                            />
                            {/* Hexagonal Shield Body */}
                            <polygon
                                points="200,19 214,27 214,43 200,51 186,43 186,27"
                                fill="#082f49"
                                stroke="#38bdf8"
                                strokeWidth="1.8"
                                strokeLinejoin="round"
                            />
                            {/* Security Crest */}
                            <path
                                d="M 200,24 L 208,28 L 208,36 C 208,41 200,45 200,45 C 200,45 192,41 192,36 L 192,28 Z"
                                fill="#0284c7"
                                stroke="#bae6fd"
                                strokeWidth="1"
                            />
                            <path
                                d="M 197,34 L 199,36 L 204,31"
                                stroke="#ffffff"
                                strokeWidth="1.2"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                fill="none"
                            />
                        </g>
                    </svg>
                ) : (
                    /* ── 2. HONORABLE CEASEFIRE: MUTUAL VERIFIED SHIELD ── */
                    <svg
                        xmlns="http://www.w3.org/2000/svg"
                        viewBox="0 0 240 70"
                        className="w-full h-full"
                        preserveAspectRatio="xMidYMid meet"
                    >
                        <style>{`
                            .ceasefire-pulse {
                                transform-origin: 120px 35px;
                                animation: softGlow 3s ease-in-out infinite alternate;
                                will-change: transform, opacity;
                            }
                            @keyframes softGlow {
                                from { transform: scale(0.97); opacity: 0.85; }
                                to { transform: scale(1.03); opacity: 1; }
                            }
                        `}</style>

                        {/* Interlocked Security Shield in Center */}
                        <g className="ceasefire-pulse">
                            {/* Verified Outer Ring */}
                            <circle
                                cx="120"
                                cy="35"
                                r="22"
                                fill="none"
                                stroke="#10b981"
                                strokeWidth="1.5"
                                strokeDasharray="16 6"
                            />
                            {/* Protected Center Hexagon */}
                            <polygon
                                points="120,18 135,26 135,44 120,52 105,44 105,26"
                                fill="#064e3b"
                                stroke="#34d399"
                                strokeWidth="2"
                                strokeLinejoin="round"
                            />
                            {/* Shield Verification Checkmark */}
                            <path
                                d="M 113,35 L 118,40 L 128,29"
                                stroke="#ffffff"
                                strokeWidth="2.5"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                fill="none"
                            />
                        </g>

                        {/* Balanced Flanking Indicators */}
                        <circle cx="50" cy="35" r="4" fill="#ef4444" opacity="0.6" />
                        <line x1="58" y1="35" x2="90" y2="35" stroke="#ef4444" strokeWidth="1" strokeDasharray="3 3" opacity="0.4" />

                        <circle cx="190" cy="35" r="4" fill="#10b981" opacity="0.7" />
                        <line x1="150" y1="35" x2="182" y2="35" stroke="#10b981" strokeWidth="1" strokeDasharray="3 3" opacity="0.4" />
                    </svg>
                )}
            </div>
        </div>
    );
}
