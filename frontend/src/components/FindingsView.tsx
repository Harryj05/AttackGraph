import React, { useState, useMemo } from 'react';
import type { GraphNode, GraphEdge } from '../types';
import { 
  ShieldAlert, 
  Terminal, 
  Flame, 
  Key, 
  Crown, 
  AlertTriangle,
  ArrowUpDown,
  Filter,
  FileText,
  Download
} from 'lucide-react';
import { getExportSarifUrl, getExportPdfUrl } from '../api/client';

interface FindingsViewProps {
  scanId?: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  onSelectFindingNode: (node: GraphNode) => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  scanId,
  nodes,
  edges,
  onSelectFindingNode,
}) => {
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [sortField, setSortField] = useState<'confidence' | 'time'>('confidence');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  // Filter finding/secret nodes
  const findingTypes = ['access_control_finding', 'reflected_input_finding', 'vulnerability', 'potential_secret'];

  const findingRows = useMemo(() => {
    const targetNodes = nodes.filter((n) => findingTypes.includes(n.node_type));

    return targetNodes.map((node) => {
      // Find incoming edge targeting this finding node
      const incomingEdge = edges.find((e) => e.target_node_id === node.id);
      const sourceNode = incomingEdge ? nodes.find((n) => n.id === incomingEdge.source_node_id) : null;

      const sourceEndpoint = sourceNode?.label || (node.properties?.endpoint as string) || (node.properties?.path as string) || 'N/A';
      const relationType = incomingEdge?.relation_type || 'N/A';
      const confidence = incomingEdge?.confidence != null ? incomingEdge.confidence : null;
      const edgeStatus = incomingEdge?.status || 'unverified';
      const createdAt = node.properties?.created_at || (incomingEdge as any)?.created_at || null;

      return {
        node,
        incomingEdge,
        sourceEndpoint,
        relationType,
        confidence,
        edgeStatus,
        createdAt,
      };
    });
  }, [nodes, edges]);

  // Apply filters & sorting
  const filteredAndSortedRows = useMemo(() => {
    return findingRows
      .filter((row) => {
        const matchesType = typeFilter === 'ALL' || 
          (typeFilter === 'ACCESS_CONTROL' && row.node.node_type === 'access_control_finding') ||
          (typeFilter === 'REFLECTED' && row.node.node_type === 'reflected_input_finding') ||
          (typeFilter === 'SECRET' && row.node.node_type === 'potential_secret') ||
          (typeFilter === 'VULNERABILITY' && row.node.node_type === 'vulnerability');

        const matchesStatus = statusFilter === 'ALL' || row.edgeStatus === statusFilter;

        return matchesType && matchesStatus;
      })
      .sort((a, b) => {
        if (sortField === 'confidence') {
          const confA = a.confidence ?? -1;
          const confB = b.confidence ?? -1;
          return sortOrder === 'desc' ? confB - confA : confA - confB;
        } else {
          const timeA = a.createdAt ? new Date(a.createdAt).getTime() : 0;
          const timeB = b.createdAt ? new Date(b.createdAt).getTime() : 0;
          return sortOrder === 'desc' ? timeB - timeA : timeA - timeB;
        }
      });
  }, [findingRows, typeFilter, statusFilter, sortField, sortOrder]);

  const toggleSort = (field: 'confidence' | 'time') => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const getIcon = (nodeType: string) => {
    if (nodeType.includes('access_control')) return <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />;
    if (nodeType.includes('reflected_input')) return <Terminal className="w-4 h-4 text-orange-400 shrink-0" />;
    if (nodeType.includes('secret')) return <Key className="w-4 h-4 text-yellow-400 shrink-0" />;
    return <Flame className="w-4 h-4 text-rose-400 shrink-0" />;
  };

  const humaniseRelation = (rel: string) => {
    if (rel === 'N/A') return 'N/A';
    switch (rel) {
      case 'access_control_check':
      case 'possible_access_control_issue':
        return 'possible access control issue';
      case 'reflected_input_check':
      case 'possible_reflected_input':
        return 'reflected input issue';
      default:
        return rel.replace(/_/g, ' ');
    }
  };

  const humaniseStatus = (st: string) => {
    switch (st) {
      case 'verified':
        return 'Verified';
      case 'unverified':
        return 'Unverified';
      case 'refuted':
        return 'Refuted';
      case 'human_invalidated':
        return 'Human invalidated';
      default:
        return st.replace(/_/g, ' ');
    }
  };

  const formatTimestamp = (ts?: string | null) => {
    if (!ts) return 'N/A';
    try {
      const d = new Date(ts);
      if (isNaN(d.getTime())) return ts;
      return d.toLocaleDateString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return ts;
    }
  };

  if (findingRows.length === 0) {
    return (
      <div className="flex-1 bg-[#0B0D1A] flex flex-col items-center justify-center text-slate-400 gap-3 p-12 select-none font-sans">
        <ShieldAlert className="w-12 h-12 text-indigo-400/40 stroke-[1.5]" />
        <span className="text-sm font-mono">No findings yet.</span>
      </div>
    );
  }

  return (
    <div className="flex-1 bg-[#0B0D1A] flex flex-col overflow-y-auto p-6 space-y-4 select-none font-sans text-slate-200">
      {/* Header & Filter Controls */}
      <div className="bg-[#12152A] border border-[#ffffff14] rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4 shadow-xl">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            Discovered Security Findings & Secrets ({filteredAndSortedRows.length})
          </h2>
          <p className="text-xs text-slate-400 font-sans">
            Consolidated table of access control issues, reflected input observations, and exposed secrets
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {scanId && (
            <div className="flex items-center gap-2 mr-2">
              <a
                href={getExportPdfUrl(scanId)}
                download
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-rose-500/15 text-rose-300 border border-rose-500/30 text-xs font-semibold hover:bg-rose-500/25 transition-all shadow-sm"
                title="Download Executive Summary PDF Report"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Export PDF</span>
              </a>
              <a
                href={getExportSarifUrl(scanId)}
                download
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 text-xs font-semibold hover:bg-indigo-500/25 transition-all shadow-sm"
                title="Download OASIS SARIF v2.1.0 JSON"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export SARIF</span>
              </a>
            </div>
          )}

          {/* Type Filter */}
          <div className="relative flex items-center">
            <Filter className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 pointer-events-none" />
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-[#0B0D1A] border border-[#ffffff14] text-xs text-slate-200 rounded-xl pl-8 pr-4 py-1.5 focus:outline-none focus:border-[#6366F1] cursor-pointer appearance-none"
            >
              <option value="ALL">All Types</option>
              <option value="ACCESS_CONTROL">Access Control</option>
              <option value="REFLECTED">Reflected Input</option>
              <option value="SECRET">Secrets</option>
              <option value="VULNERABILITY">Vulnerabilities</option>
            </select>
          </div>

          {/* Status Filter */}
          <div className="relative flex items-center">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-[#0B0D1A] border border-[#ffffff14] text-xs text-slate-200 rounded-xl px-3 py-1.5 focus:outline-none focus:border-[#6366F1] cursor-pointer appearance-none"
            >
              <option value="ALL">All Edge Statuses</option>
              <option value="verified">Verified</option>
              <option value="unverified">Unverified</option>
              <option value="refuted">Refuted</option>
              <option value="human_invalidated">Human Invalidated</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-[#12152A] border border-[#ffffff14] rounded-2xl overflow-hidden shadow-xl">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-[#0B0D1A] border-b border-[#ffffff14] text-[12px] font-medium text-slate-400 select-none">
              <th className="p-3.5">Finding Label</th>
              <th className="p-3.5">Type</th>
              <th className="p-3.5">Source Endpoint</th>
              <th className="p-3.5">Relation</th>
              <th className="p-3.5 cursor-pointer hover:text-slate-200" onClick={() => toggleSort('confidence')}>
                <div className="flex items-center gap-1">
                  <span>Confidence</span>
                  <ArrowUpDown className="w-3 h-3 text-indigo-400" />
                </div>
              </th>
              <th className="p-3.5">Status</th>
              <th className="p-3.5">Flags</th>
              <th className="p-3.5 cursor-pointer hover:text-slate-200" onClick={() => toggleSort('time')}>
                <div className="flex items-center gap-1">
                  <span>Discovered</span>
                  <ArrowUpDown className="w-3 h-3 text-indigo-400" />
                </div>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#ffffff0a] text-xs">
            {filteredAndSortedRows.map((row) => {
              const node = row.node;
              const confText = row.confidence != null ? row.confidence.toFixed(2) : 'N/A';

              let statusStyle = 'bg-amber-500/15 text-amber-400 border-amber-500/30';
              if (row.edgeStatus === 'verified') statusStyle = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
              if (row.edgeStatus === 'refuted') statusStyle = 'bg-slate-500/15 text-slate-400 border-slate-500/30';
              if (row.edgeStatus === 'human_invalidated') statusStyle = 'bg-pink-500/15 text-pink-400 border-pink-500/30';

              const createdTime = node.created_at || (node.properties?.created_at as string) || row.createdAt;

              return (
                <tr
                  key={node.id}
                  onClick={() => onSelectFindingNode(node)}
                  className="hover:bg-[#1A1D3B]/60 transition-colors cursor-pointer"
                >
                  {/* Label */}
                  <td className="p-3.5 font-semibold text-slate-100 max-w-[220px] truncate">
                    <div className="flex items-center gap-2">
                      {getIcon(node.node_type)}
                      <span className="truncate" title={node.label}>{node.label}</span>
                    </div>
                  </td>

                  {/* Type Badge */}
                  <td className="p-3.5">
                    <span className="text-[11px] font-sans px-2 py-0.5 rounded-md bg-[#6366F1]/15 text-indigo-300 border border-[#6366F1]/30">
                      {node.node_type.replace(/_/g, ' ')}
                    </span>
                  </td>

                  {/* Source Endpoint */}
                  <td className="p-3.5 font-mono text-indigo-300 max-w-[180px] truncate">
                    <span title={row.sourceEndpoint}>{row.sourceEndpoint}</span>
                  </td>

                  {/* Relation */}
                  <td className="p-3.5 text-slate-300">
                    {humaniseRelation(row.relationType)}
                  </td>

                  {/* Confidence (Neutral color) */}
                  <td className="p-3.5 font-mono font-semibold text-slate-200">
                    {confText}
                  </td>

                  {/* Status (Humanised sentence case) */}
                  <td className="p-3.5">
                    <span className={`text-[11px] font-sans px-2 py-0.5 rounded-md border ${statusStyle}`}>
                      {humaniseStatus(row.edgeStatus)}
                    </span>
                  </td>

                  {/* Flags & Standard Tags */}
                  <td className="p-3.5">
                    <div className="flex flex-wrap items-center gap-1.5">
                      {node.is_critical && (
                        <span className="p-1 rounded bg-rose-500/20 text-rose-400" title="Critical Bottleneck">
                          <Crown className="w-3.5 h-3.5" />
                        </span>
                      )}
                      {node.undermined && (
                        <span className="p-1 rounded bg-amber-500/20 text-amber-400" title="Undermined Node">
                          <AlertTriangle className="w-3.5 h-3.5" />
                        </span>
                      )}
                      {node.properties?.cwe && (
                        <span 
                          className="px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/40 text-[10px] font-mono flex items-center gap-0.5"
                          title={node.properties.cwe_mapping === 'potential' ? 'Potential mapping' : 'CWE classification'}
                        >
                          <span>{node.properties.cwe}</span>
                          {node.properties.cwe_mapping === 'potential' && (
                            <span className="text-[9px] text-amber-400 italic">?</span>
                          )}
                        </span>
                      )}
                      {node.properties?.owasp && (
                        <span 
                          className="px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 text-[10px] font-mono"
                          title="OWASP Category"
                        >
                          {node.properties.owasp}
                        </span>
                      )}
                      {!node.is_critical && !node.undermined && !node.properties?.cwe && !node.properties?.owasp && (
                        <span className="text-slate-600 font-mono text-[10px]">-</span>
                      )}
                    </div>
                  </td>

                  {/* Discovered Time */}
                  <td className="p-3.5 text-slate-400 font-sans text-[11px]">
                    {formatTimestamp(createdTime)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
