import React, { useState } from 'react';
import type { Scan, GraphData } from '../types';
import { FolderKanban, Copy, Check, ArrowRight } from 'lucide-react';

interface ScansViewProps {
  scans: Scan[];
  selectedScanId: string;
  onSelectScan: (scanId: string) => void;
  onNavigateToGraph: () => void;
  graphData: GraphData | null;
}

export const ScansView: React.FC<ScansViewProps> = ({
  scans,
  selectedScanId,
  onSelectScan,
  onNavigateToGraph,
  graphData,
}) => {
  const [copiedScanId, setCopiedScanId] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedScanId(id);
    setTimeout(() => setCopiedScanId(null), 1500);
  };

  const statusChip = (st: string) => {
    const up = st.toUpperCase();
    if (up.includes('RUNNING')) {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-mono font-semibold text-[#b45309]">
          <span className="w-2 h-2 rounded-full bg-amber-500 animate-ping" /> Running
        </span>
      );
    }
    if (up.includes('COMPLETED')) {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-mono font-semibold text-[#0b7a83]">
          <span className="w-2 h-2 rounded-full bg-[#0b7a83]" /> Completed
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-mono font-semibold text-[#7a8596]">
        <span className="w-2 h-2 rounded-full bg-[#7a8596]" /> {st}
      </span>
    );
  };

  const fmtDate = (ts: string) => {
    try {
      const d = new Date(ts);
      if (isNaN(d.getTime())) return ts;
      return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    } catch {
      return ts;
    }
  };

  if (scans.length === 0) {
    return (
      <div className="flex-1 min-h-0 bg-[#eef1f5] flex flex-col items-center justify-center text-[#4a5566] gap-3 p-12 select-none text-center">
        <FolderKanban className="w-12 h-12 text-[#0b7a83]/50 stroke-[1.5]" />
        <span className="text-base font-semibold text-[#18202c]">No case files yet</span>
        <span className="text-sm max-w-[380px]">Open a case file by running a scan from the top bar — each target you examine is logged here.</span>
      </div>
    );
  }

  return (
    <div className="flex-1 min-h-0 bg-[#eef1f5] flex flex-col overflow-y-auto p-6 select-none text-[#18202c]">
      {/* Header — TraceMap "case files" treatment */}
      <div className="mb-5">
        <p className="eyebrow mb-1.5">Case register</p>
        <h2 className="text-2xl font-extrabold tracking-tight">Recent case files ({scans.length})</h2>
        <p className="text-sm text-[#4a5566] mt-1">
          Every target examined, with its topology and verdict. Select a row to open its attack graph.
        </p>
      </div>

      {/* Ledger table */}
      <div className="bg-[#f8f9fb] border border-[#18202c1f] rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b-2 border-[#18202c]">
                <th className="p-3.5 font-mono text-[11px] uppercase tracking-wider text-[#7a8596]">Case ID</th>
                <th className="p-3.5 font-mono text-[11px] uppercase tracking-wider text-[#7a8596]">Target</th>
                <th className="p-3.5 font-mono text-[11px] uppercase tracking-wider text-[#7a8596]">Status</th>
                <th className="p-3.5 font-mono text-[11px] uppercase tracking-wider text-[#7a8596] text-right">Nodes</th>
                <th className="p-3.5 font-mono text-[11px] uppercase tracking-wider text-[#7a8596] text-right">Edges</th>
                <th className="p-3.5 font-mono text-[11px] uppercase tracking-wider text-[#7a8596]">Opened</th>
                <th className="p-3.5" />
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => {
                const isSelected = scan.id === selectedScanId;
                const isCurrentGraph = isSelected && graphData?.scan_id === scan.id;
                return (
                  <tr
                    key={scan.id}
                    onClick={() => {
                      onSelectScan(scan.id);
                      onNavigateToGraph();
                    }}
                    className={`group cursor-pointer border-b border-[#18202c12] last:border-b-0 transition-colors ${
                      isSelected ? 'bg-[#0b7a83]/8' : 'hover:bg-[#eef1f5]'
                    }`}
                    style={isSelected ? { boxShadow: 'inset 3px 0 0 #0b7a83' } : undefined}
                  >
                    <td className="p-3.5">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-sm font-bold text-[#0b7a83]">#{scan.id.slice(0, 8)}</span>
                        <button
                          onClick={(e) => copyToClipboard(scan.id, scan.id, e)}
                          className="text-[#7a8596] hover:text-[#18202c] p-0.5 rounded cursor-pointer opacity-0 group-hover:opacity-100 transition-opacity"
                          title="Copy full Scan ID"
                        >
                          {copiedScanId === scan.id ? <Check className="w-3.5 h-3.5 text-[#0b7a83]" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </td>
                    <td className="p-3.5 font-mono text-sm text-[#18202c] max-w-[260px] truncate" title={scan.target_url}>
                      {scan.target_url}
                    </td>
                    <td className="p-3.5">{statusChip(scan.status)}</td>
                    <td className="p-3.5 text-right font-mono text-sm text-[#4a5566]">
                      {isCurrentGraph ? graphData?.nodes.length : '—'}
                    </td>
                    <td className="p-3.5 text-right font-mono text-sm text-[#4a5566]">
                      {isCurrentGraph ? graphData?.edges.length : '—'}
                    </td>
                    <td className="p-3.5 text-sm text-[#7a8596] whitespace-nowrap">{fmtDate(scan.created_at)}</td>
                    <td className="p-3.5 text-right">
                      <ArrowRight className="w-4 h-4 text-[#0b7a83] opacity-0 group-hover:opacity-100 group-hover:translate-x-0.5 transition-all inline-block" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
