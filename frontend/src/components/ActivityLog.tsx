import React, { useState } from 'react';
import type { AgentLog } from '../types';
import { CheckCircle2, XCircle, ChevronLeft, ChevronRight, ListFilter, Terminal } from 'lucide-react';

interface ActivityLogProps {
  logs: AgentLog[];
  loading: boolean;
  activeStepNumber?: number | null;
  onSelectStep?: (stepNumber: number) => void;
  isOpen?: boolean;
  onToggle?: () => void;
}

export const ActivityLog: React.FC<ActivityLogProps> = ({
  logs,
  loading,
  activeStepNumber,
  onSelectStep,
  isOpen,
  onToggle,
}) => {
  const [internalCollapsed, setInternalCollapsed] = useState(true);
  const collapsed = isOpen !== undefined ? !isOpen : internalCollapsed;

  const handleToggle = () => {
    if (onToggle) {
      onToggle();
    } else {
      setInternalCollapsed((prev) => !prev);
    }
  };

  if (collapsed) {
    return (
      <aside className="w-10 bg-[#eef1f5] border-r border-[#dde3ea] flex flex-col items-center py-3 select-none shrink-0 transition-all">
        <button
          onClick={handleToggle}
          className="p-1.5 text-[#4a5566] hover:text-[#4a5566] rounded hover:bg-[#dde3ea] cursor-pointer"
          title="Expand Activity Log"
        >
          <ChevronRight className="w-4 h-4" />
        </button>
        <div className="mt-4 rotate-90 origin-left text-xs font-mono text-[#4a5566] tracking-widest uppercase whitespace-nowrap">
          Activity Log ({logs.length})
        </div>
      </aside>
    );
  }

  return (
    <aside className="w-64 bg-[#eef1f5] border-r border-[#dde3ea] flex flex-col shrink-0 select-none transition-all z-10">
      {/* Header */}
      <div className="h-10 px-3 border-b border-[#dde3ea] flex items-center justify-between bg-[#eef1f5]/50">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-[#4a5566]">
          <ListFilter className="w-3.5 h-3.5 text-[#FFAA00]" />
          <span>Agent Activity</span>
          <span className="px-1.5 py-0.2 rounded bg-[#dde3ea] text-[#4a5566] text-[10px] font-mono">
            {logs.length}
          </span>
        </div>
        <button
          onClick={handleToggle}
          className="p-1 text-[#4a5566] hover:text-[#4a5566] rounded hover:bg-[#dde3ea] cursor-pointer"
          title="Collapse Sidebar"
        >
          <ChevronLeft className="w-4 h-4" />
        </button>
      </div>

      {/* Log list */}
      <div className="flex-1 overflow-y-auto p-2 space-y-2">
        {loading ? (
          <div className="text-xs text-[#7a8596] font-mono text-center py-6 animate-pulse">
            Loading activity log...
          </div>
        ) : logs.length === 0 ? (
          <div className="text-xs text-[#7a8596] font-mono text-center py-6">
            No agent steps logged for this scan.
          </div>
        ) : (
          logs.map((log) => {
            const isError = log.observation?.toLowerCase().includes('error') || log.observation?.toLowerCase().includes('rejected') || log.observation?.toLowerCase().includes('failed');
            const isActive = activeStepNumber !== undefined && activeStepNumber !== null && log.step_number === activeStepNumber;

            return (
              <div
                key={log.id || log.step_number}
                onClick={() => onSelectStep?.(log.step_number)}
                className={`border rounded p-2.5 text-xs transition-all cursor-pointer ${
                  isActive
                    ? 'bg-[#E040FB]/15 border-[#E040FB] ring-2 ring-[#E040FB]/40 shadow-lg'
                    : 'bg-[#eef1f5] border-[#dde3ea] hover:border-[#c8d0da]'
                }`}
              >
                {/* Step header */}
                <div className="flex items-center justify-between gap-1 mb-1">
                  <span className="font-mono text-[#FFAA00] font-semibold text-[11px]">
                    Step #{log.step_number}
                  </span>
                  <div className="flex items-center gap-1">
                    {isError ? (
                      <XCircle className="w-3.5 h-3.5 text-[#FF3B3B] shrink-0" />
                    ) : (
                      <CheckCircle2 className="w-3.5 h-3.5 text-[#00E676] shrink-0" />
                    )}
                  </div>
                </div>

                {/* Action / Tool badge */}
                {log.action && (
                  <div className="mb-1.5">
                    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#1a2030] text-[#4a5566] border border-[#c8d0da]">
                      <Terminal className="w-3 h-3 text-[#4a5566]" />
                      <span className="truncate max-w-[170px]">{log.action}</span>
                    </span>
                  </div>
                )}

                {/* Thought text */}
                {log.thought && (
                  <p className="text-[#4a5566] text-[11px] leading-relaxed mb-1 line-clamp-2">
                    {log.thought}
                  </p>
                )}

                {/* Observation snippet */}
                {log.observation && (
                  <div className="font-mono text-[10px] bg-[#eef1f5] p-1.5 rounded border border-[#dde3ea] text-[#4a5566] line-clamp-2 break-all">
                    {log.observation}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </aside>
  );
};
