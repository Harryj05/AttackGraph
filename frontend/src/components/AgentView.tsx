import React, { useState, useMemo } from 'react';
import type { AgentLog } from '../types';
import { 
  Bot, 
  Terminal, 
  CheckCircle2, 
  AlertCircle, 
  ChevronDown, 
  ChevronRight, 
  PlayCircle,
  Copy,
  Check,
  Zap,
  Filter,
  Cpu,
  Play
} from 'lucide-react';

interface AgentViewProps {
  agentLogs: AgentLog[];
  loading: boolean;
  onSelectStepForReplay?: (stepNumber: number) => void;
  scanMode?: 'agent' | 'deterministic';
  onChangeScanMode?: (mode: 'agent' | 'deterministic') => void;
  onRunScan?: () => void;
  isRunningScan?: boolean;
  lastRunMetrics?: any;
}

export const AgentView: React.FC<AgentViewProps> = ({
  agentLogs,
  loading,
  onSelectStepForReplay,
  scanMode = 'agent',
  onChangeScanMode,
  onRunScan,
  isRunningScan = false,
  lastRunMetrics,
}) => {
  const [filterMode, setFilterMode] = useState<string>('ALL');
  const [expandedLogIds, setExpandedLogIds] = useState<Set<string>>(new Set());
  const [copiedLogId, setCopiedLogId] = useState<string | null>(null);

  const toggleExpand = (id: string) => {
    setExpandedLogIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedLogId(id);
    setTimeout(() => setCopiedLogId(null), 1500);
  };

  // Helper to extract tool name from action string like "execute_nmap_scan(...)"
  const parseAction = (actionStr?: string | null) => {
    if (!actionStr) return { toolName: 'no_action', args: '' };
    const match = actionStr.match(/^([a-zA-Z0-9_]+)\((.*)\)$/s);
    if (match) {
      return { toolName: match[1], args: match[2] };
    }
    return { toolName: actionStr, args: '' };
  };

  // Calculate stats & counts
  const stats = useMemo(() => {
    let successes = 0;
    let errors = 0;
    const toolCounts: Record<string, number> = {};

    agentLogs.forEach((log) => {
      const obs = (log.observation || '').toLowerCase();
      const action = (log.action || '').toLowerCase();

      if (obs.includes('error') || obs.includes('fail') || action.includes('api_error')) {
        errors++;
      } else if (obs.includes('success') || obs.includes('completed')) {
        successes++;
      }

      const { toolName } = parseAction(log.action);
      if (toolName && toolName !== 'no_action') {
        toolCounts[toolName] = (toolCounts[toolName] || 0) + 1;
      }
    });

    return { total: agentLogs.length, successes, errors, toolCounts };
  }, [agentLogs]);

  // Filter logs
  const filteredLogs = useMemo(() => {
    return agentLogs.filter((log) => {
      const obs = (log.observation || '').toLowerCase();
      const action = (log.action || '').toLowerCase();
      const { toolName } = parseAction(log.action);

      if (filterMode === 'ALL') return true;
      if (filterMode === 'ERRORS') {
        return obs.includes('error') || obs.includes('fail') || action.includes('api_error');
      }
      return toolName === filterMode;
    });
  }, [agentLogs, filterMode]);

  // Group consecutive logs by step_number
  const groupedLogs = useMemo(() => {
    const groups: { stepNumber: number; logs: AgentLog[] }[] = [];
    filteredLogs.forEach((log) => {
      const lastGroup = groups[groups.length - 1];
      if (lastGroup && lastGroup.stepNumber === log.step_number) {
        lastGroup.logs.push(log);
      } else {
        groups.push({ stepNumber: log.step_number, logs: [log] });
      }
    });
    return groups;
  }, [filteredLogs]);

  if (loading) {
    return (
      <div className="flex-1 bg-[#0B0D1A] flex flex-col items-center justify-center text-xs font-mono text-indigo-400 gap-3 p-12">
        <Bot className="w-8 h-8 animate-bounce text-indigo-400" />
        <span>Loading agent decision trajectory logs...</span>
      </div>
    );
  }

  const renderModeControls = () => (
    <div className="bg-[#12152A] border border-[#ffffff14] rounded-2xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-lg">
      <div className="flex items-center gap-3">
        <span className="text-xs font-mono text-slate-400 font-semibold uppercase tracking-wider">Scan Mode:</span>
        <div className="flex bg-[#0B0D1A] p-1 rounded-xl border border-[#ffffff14]">
          <button
            onClick={() => onChangeScanMode && onChangeScanMode('agent')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono flex items-center gap-2 transition-all cursor-pointer ${
              scanMode === 'agent'
                ? 'bg-[#6366F1] text-white font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Bot className="w-3.5 h-3.5" />
            Agent (Gemini LLM Loop)
          </button>
          <button
            onClick={() => onChangeScanMode && onChangeScanMode('deterministic')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono flex items-center gap-2 transition-all cursor-pointer ${
              scanMode === 'deterministic'
                ? 'bg-emerald-600 text-white font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            Deterministic (Fixed Pipeline)
          </button>
        </div>
      </div>

      {onRunScan && (
        <button
          onClick={onRunScan}
          disabled={isRunningScan}
          className={`px-4 py-2 rounded-xl text-xs font-mono flex items-center gap-2 transition-all cursor-pointer shadow-md ${
            isRunningScan
              ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
              : scanMode === 'deterministic'
              ? 'bg-emerald-600 hover:bg-emerald-500 text-white font-bold'
              : 'bg-[#6366F1] hover:bg-[#4F46E5] text-white font-bold'
          }`}
        >
          {isRunningScan ? (
            <>
              <div className="w-3.5 h-3.5 border-2 border-white/20 border-t-white rounded-full animate-spin" />
              Running {scanMode}...
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              Run Scan ({scanMode.toUpperCase()})
            </>
          )}
        </button>
      )}
    </div>
  );

  const renderMetricsCard = () => {
    if (!lastRunMetrics) return null;
    return (
      <div className="bg-[#12152A] border border-[#ffffff14] rounded-2xl p-4 shadow-md">
        <div className="flex items-center justify-between pb-3 border-b border-[#ffffff0f]">
          <span className="text-xs font-mono font-bold text-slate-300 flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            Latest Run Telemetry ({lastRunMetrics.mode || scanMode})
          </span>
          <span className="text-xs font-mono text-slate-400">
            Wall-clock: <strong className="text-slate-200">{lastRunMetrics.wall_clock_time}s</strong>
          </span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-3 text-xs font-mono">
          <div className="bg-[#0B0D1A] p-2.5 rounded-xl border border-[#ffffff0f]">
            <span className="text-slate-400 block text-[11px]">Valid Findings</span>
            <span className="text-emerald-400 font-bold text-sm">{lastRunMetrics.valid_findings ?? 0}</span>
          </div>
          <div className="bg-[#0B0D1A] p-2.5 rounded-xl border border-[#ffffff0f]">
            <span className="text-slate-400 block text-[11px]">False Positives</span>
            <span className="text-rose-400 font-bold text-sm">{lastRunMetrics.false_positives ?? 0}</span>
          </div>
          <div className="bg-[#0B0D1A] p-2.5 rounded-xl border border-[#ffffff0f]">
            <span className="text-slate-400 block text-[11px]">Token Usage / Cost</span>
            <span className="text-indigo-400 font-bold text-sm">
              {lastRunMetrics.token_usage?.total_tokens ?? 0} tkns (${(lastRunMetrics.estimated_cost ?? 0).toFixed(4)})
            </span>
          </div>
          <div className="bg-[#0B0D1A] p-2.5 rounded-xl border border-[#ffffff0f]">
            <span className="text-slate-400 block text-[11px]">Refusals / Rejections</span>
            <span className="text-amber-400 font-bold text-sm">
              {lastRunMetrics.refusals ?? 0} ref / {lastRunMetrics.guardrail_rejections ?? 0} rej
            </span>
          </div>
        </div>
      </div>
    );
  };

  if (agentLogs.length === 0) {
    return (
      <div className="flex-1 bg-[#0B0D1A] flex flex-col p-6 space-y-6 select-none font-sans text-slate-200">
        {renderModeControls()}
        {renderMetricsCard()}
        <div className="flex-1 flex flex-col items-center justify-center text-slate-400 gap-3 py-16">
          <Bot className="w-12 h-12 text-indigo-400/40 stroke-[1.5]" />
          <span className="text-sm font-mono">No scan activity logged yet for this scan. Select mode and run above.</span>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 bg-[#0B0D1A] flex flex-col overflow-y-auto p-6 space-y-6 select-none font-sans text-slate-200">
      {renderModeControls()}
      {renderMetricsCard()}
      {/* 1. Summary Header & Filter Bar */}
      <div className="bg-[#12152A] border border-[#ffffff14] rounded-2xl p-5 space-y-4 shadow-xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#6366F1]/15 border border-[#6366F1]/40 flex items-center justify-center text-[#6366F1]">
              <Bot className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                Autonomous Agent Execution Log
              </h2>
              <p className="text-xs text-slate-400 font-sans">
                Full reasoning, tool calls, and observations from the LLM decision loop
              </p>
            </div>
          </div>

          {/* Quick Metrics */}
          <div className="flex items-center gap-4 text-xs font-mono">
            <div className="bg-[#0B0D1A] border border-[#ffffff14] px-3 py-1.5 rounded-xl flex items-center gap-2">
              <span className="text-slate-400">Total Steps:</span>
              <span className="text-slate-100 font-bold">{stats.total}</span>
            </div>
            <div className="bg-[#0B0D1A] border border-emerald-500/30 px-3 py-1.5 rounded-xl flex items-center gap-2">
              <span className="text-emerald-400">Successes:</span>
              <span className="text-emerald-400 font-bold">{stats.successes}</span>
            </div>
            <div className="bg-[#0B0D1A] border border-rose-500/30 px-3 py-1.5 rounded-xl flex items-center gap-2">
              <span className="text-rose-400">Errors:</span>
              <span className="text-rose-400 font-bold">{stats.errors}</span>
            </div>
          </div>
        </div>

        {/* Filter Chips */}
        <div className="flex items-center gap-2 pt-2 border-t border-[#ffffff0f] overflow-x-auto">
          <span className="text-xs font-mono text-slate-400 flex items-center gap-1 mr-2">
            <Filter className="w-3.5 h-3.5" /> Filter:
          </span>
          <button
            onClick={() => setFilterMode('ALL')}
            className={`px-3 py-1 rounded-xl text-xs font-mono transition-all cursor-pointer ${
              filterMode === 'ALL'
                ? 'bg-[#6366F1] text-white font-semibold shadow-sm'
                : 'bg-[#0B0D1A] text-slate-400 hover:text-slate-200 border border-[#ffffff14]'
            }`}
          >
            All ({agentLogs.length})
          </button>
          <button
            onClick={() => setFilterMode('ERRORS')}
            className={`px-3 py-1 rounded-xl text-xs font-mono transition-all cursor-pointer ${
              filterMode === 'ERRORS'
                ? 'bg-rose-500 text-white font-semibold shadow-sm'
                : 'bg-[#0B0D1A] text-slate-400 hover:text-rose-400 border border-[#ffffff14]'
            }`}
          >
            Errors ({stats.errors})
          </button>

          {Object.entries(stats.toolCounts).map(([tName, count]) => (
            <button
              key={tName}
              onClick={() => setFilterMode(tName)}
              className={`px-3 py-1 rounded-xl text-xs font-mono transition-all cursor-pointer ${
                filterMode === tName
                  ? 'bg-indigo-500 text-white font-semibold shadow-sm'
                  : 'bg-[#0B0D1A] text-slate-400 hover:text-slate-200 border border-[#ffffff14]'
              }`}
            >
              {tName} ({count})
            </button>
          ))}
        </div>
      </div>

      {/* 2. Vertical Timeline Container */}
      <div className="space-y-6 relative before:absolute before:left-6 before:top-4 before:bottom-4 before:w-0.5 before:bg-[#ffffff14]">
        {groupedLogs.map((group) => (
          <div key={`step-group-${group.stepNumber}`} className="space-y-4 relative pl-12">
            {/* Step Group Marker */}
            <div className="absolute left-2 top-0 -translate-x-1/2 flex items-center justify-center w-8 h-8 rounded-full bg-[#12152A] border-2 border-[#6366F1] text-indigo-400 font-mono text-xs font-bold shadow-lg z-10">
              #{group.stepNumber}
            </div>

            {/* Header row for Step Number */}
            <div className="flex items-center justify-between pb-1">
              <div className="flex items-center gap-3">
                <span className="text-xs font-mono font-bold text-slate-100 uppercase tracking-wider">
                  Step #{group.stepNumber}
                </span>
                {onSelectStepForReplay && (
                  <button
                    onClick={() => onSelectStepForReplay(group.stepNumber)}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#6366F1]/15 text-[#6366F1] border border-[#6366F1]/30 hover:bg-[#6366F1]/25 text-[11px] font-mono cursor-pointer transition-all"
                  >
                    <PlayCircle className="w-3.5 h-3.5" />
                    <span>View in Replay</span>
                  </button>
                )}
              </div>
            </div>

            {/* Log Cards under this step (React key uses log.id!) */}
            <div className="space-y-3">
              {group.logs.map((log) => {
                const { toolName, args } = parseAction(log.action);
                const obs = log.observation || '';
                const isError = obs.toLowerCase().includes('error') || obs.toLowerCase().includes('fail') || (log.action || '').includes('api_error');
                const isSuccess = obs.toLowerCase().includes('success') || obs.toLowerCase().includes('completed');
                const isExpanded = expandedLogIds.has(log.id);

                let cardBorder = 'border-[#ffffff14]';
                let obsBg = 'bg-[#0B0D1A] text-slate-300 border-[#ffffff0a]';

                if (isError) {
                  cardBorder = 'border-rose-500/40 bg-rose-500/5';
                  obsBg = 'bg-rose-500/10 text-rose-300 border-rose-500/30';
                } else if (isSuccess) {
                  obsBg = 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30';
                }

                return (
                  <div
                    key={log.id}
                    className={`bg-[#12152A] border rounded-2xl p-4 space-y-3 transition-all shadow-lg ${cardBorder}`}
                  >
                    {/* Log Header & Timestamp */}
                    <div className="flex items-center justify-between text-xs font-mono">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-400">LOG ID:</span>
                        <span className="text-indigo-300 font-semibold">#{log.id.slice(0, 8)}</span>
                      </div>
                      <span className="text-slate-500">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    {/* Thought Block */}
                    {log.thought && (
                      <div className="space-y-1">
                        <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                          Agent Thought
                        </span>
                        <p className="text-xs text-slate-200 leading-relaxed font-sans bg-[#0B0D1A] p-3 rounded-xl border border-[#ffffff0a]">
                          {log.thought}
                        </p>
                      </div>
                    )}

                    {/* Action Block */}
                    {toolName !== 'no_action' && (
                      <div className="space-y-1.5">
                        <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                          Tool Action
                        </span>
                        <div className="bg-[#0B0D1A] border border-[#ffffff0a] rounded-xl p-3 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-indigo-500/15 text-indigo-300 font-mono text-xs font-bold border border-indigo-500/30">
                              <Terminal className="w-3.5 h-3.5 text-indigo-400" />
                              {toolName}
                            </span>

                            {args && (
                              <button
                                onClick={() => toggleExpand(log.id)}
                                className="text-[11px] font-mono text-indigo-400 hover:underline flex items-center gap-1 cursor-pointer"
                              >
                                {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                                <span>{isExpanded ? 'Hide Arguments' : 'View Arguments'}</span>
                              </button>
                            )}
                          </div>

                          {args && isExpanded && (
                            <div className="relative">
                              <pre className="p-2.5 bg-[#12152A] text-indigo-200 font-mono text-[11px] rounded-lg border border-[#ffffff0a] overflow-x-auto whitespace-pre-wrap break-all">
                                {args}
                              </pre>
                              <button
                                onClick={() => copyToClipboard(args, log.id)}
                                className="absolute top-2 right-2 text-slate-400 hover:text-slate-200 p-1 rounded bg-[#0B0D1A] cursor-pointer"
                                title="Copy tool args"
                              >
                                {copiedLogId === log.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Observation Block */}
                    {log.observation && (
                      <div className="space-y-1">
                        <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                          Observation
                        </span>
                        <div className={`p-3 rounded-xl border font-mono text-xs leading-relaxed flex items-start gap-2 ${obsBg}`}>
                          {isError ? (
                            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                          ) : isSuccess ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                          ) : (
                            <Zap className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
                          )}
                          <div className="whitespace-pre-wrap break-all flex-1">
                            {log.observation}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
