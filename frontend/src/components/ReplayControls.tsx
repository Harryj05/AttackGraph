import React from 'react';
import { Play, Pause, SkipForward, SkipBack, RotateCcw, History } from 'lucide-react';
import type { ReplayEvent, GraphNode, GraphEdge } from '../types';

interface ReplayControlsProps {
  events: ReplayEvent[];
  currentIndex: number;
  isPlaying: boolean;
  onIndexChange: (index: number) => void;
  onPlayPause: () => void;
  onReset: () => void;
  speed?: number;
  onSpeedChange?: (speed: number) => void;
}

export const ReplayControls: React.FC<ReplayControlsProps> = ({
  events,
  currentIndex,
  isPlaying,
  onIndexChange,
  onPlayPause,
  onReset,
  speed = 1,
  onSpeedChange,
}) => {
  if (events.length === 0) {
    return (
      <div className="bg-[#f8f9fb] border-t border-[#18202c1f] px-6 py-3 flex items-center justify-center text-xs font-mono text-[#4a5566] gap-2">
        <History className="w-4 h-4 text-[#0b7a83]" />
        <span>No replay events found for this scan.</span>
      </div>
    );
  }

  const currentEvent = events[currentIndex];
  const maxIndex = events.length - 1;

  const getEventDetailText = (event?: ReplayEvent) => {
    if (!event) return 'Initialization';
    if (event.event_type === 'node_created') {
      const node = event.data as GraphNode;
      const stepStr = event.step_number != null ? ` (Step ${event.step_number})` : '';
      return `Created Node [${node.node_type}]: ${node.label}${stepStr}`;
    } else {
      const edge = event.data as GraphEdge;
      const stepStr = event.step_number != null ? ` (Step ${event.step_number})` : '';
      return `Created Edge [${edge.relation_type}]: ${edge.status}${stepStr}`;
    }
  };

  const handleStepBack = () => {
    if (currentIndex > 0) onIndexChange(currentIndex - 1);
  };

  const handleStepForward = () => {
    if (currentIndex < maxIndex) onIndexChange(currentIndex + 1);
  };

  return (
    <div className="h-16 bg-[#f8f9fb]/95 backdrop-blur-md border-t border-[#18202c1f] px-4 flex items-center justify-between gap-4 z-30 select-none shadow-2xl shrink-0 text-xs font-mono">
      {/* Playback Controls & Range Scrubber */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="flex items-center gap-1 bg-[#eef1f5] p-1 rounded-xl border border-[#18202c1f]">
          <button
            onClick={onReset}
            className="p-1 text-[#4a5566] hover:text-[#18202c] hover:bg-[#e4e8ee]/50 rounded-lg transition-colors cursor-pointer"
            title="Reset to beginning"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>

          <button
            onClick={handleStepBack}
            disabled={currentIndex <= 0}
            className="p-1 text-[#4a5566] hover:text-[#18202c] hover:bg-[#e4e8ee]/50 rounded-lg transition-colors cursor-pointer disabled:opacity-30 disabled:hover:bg-transparent"
            title="Step Back"
          >
            <SkipBack className="w-3.5 h-3.5" />
          </button>

          <button
            onClick={onPlayPause}
            className="p-1.5 bg-[#0b7a83] hover:bg-[#095f66] text-white font-bold rounded-lg transition-all shadow-md flex items-center justify-center cursor-pointer"
            title={isPlaying ? 'Pause' : 'Play'}
          >
            {isPlaying ? <Pause className="w-3.5 h-3.5 fill-current" /> : <Play className="w-3.5 h-3.5 fill-current ml-0.5" />}
          </button>

          <button
            onClick={handleStepForward}
            disabled={currentIndex >= maxIndex}
            className="p-1 text-[#4a5566] hover:text-[#18202c] hover:bg-[#e4e8ee]/50 rounded-lg transition-colors cursor-pointer disabled:opacity-30 disabled:hover:bg-transparent"
            title="Step Forward"
          >
            <SkipForward className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Speed Selector */}
        {onSpeedChange && (
          <div className="flex items-center bg-[#eef1f5] border border-[#18202c1f] rounded-xl p-0.5 text-xs">
            {[0.5, 1, 2].map((s) => (
              <button
                key={s}
                onClick={() => onSpeedChange(s)}
                className={`px-2 py-0.5 rounded-lg transition-all cursor-pointer text-[11px] ${
                  speed === s
                    ? 'bg-[#0b7a83] text-white font-bold'
                    : 'text-[#4a5566] hover:text-[#18202c]'
                }`}
              >
                {s}x
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Center: Range Scrubber */}
      <div className="flex-1 max-w-xl flex items-center gap-3">
        <input
          type="range"
          min={0}
          max={maxIndex}
          value={currentIndex}
          onChange={(e) => onIndexChange(Number(e.target.value))}
          className="w-full h-1.5 bg-[#eef1f5] rounded-lg appearance-none cursor-pointer accent-[#0b7a83]"
        />
      </div>

      {/* Right: Counter & Truncated Event Readout */}
      <div className="flex items-center gap-3 shrink-0 min-w-0">
        <span className="text-[#18202c] font-semibold shrink-0">
          Event {currentIndex + 1}/{events.length}
          {currentEvent?.step_number != null && (
            <span className="text-[#0b7a83] ml-1">(Step #{currentEvent.step_number})</span>
          )}
        </span>

        <div 
          className="text-[#4a5566] truncate max-w-[280px] bg-[#eef1f5] px-2.5 py-1 rounded-xl border border-[#18202c1f] flex items-center gap-1.5 shrink-0"
          title={getEventDetailText(currentEvent)}
        >
          <span className={`text-[9px] font-bold px-1 py-0.2 rounded uppercase shrink-0 ${
            currentEvent?.event_type === 'node_created' ? 'bg-[#0b7a83]/20 text-[#0b7a83]' : 'bg-cyan-500/20 text-cyan-400'
          }`}>
            {currentEvent?.event_type === 'node_created' ? 'NODE' : 'EDGE'}
          </span>
          <span className="truncate text-xs">{getEventDetailText(currentEvent)}</span>
        </div>
      </div>
    </div>
  );
};
