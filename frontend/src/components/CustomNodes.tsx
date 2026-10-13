import { memo } from 'react';
import { Handle, Position } from '@xyflow/react';
import type { NodeProps, Node } from '@xyflow/react';
import type { GraphNode } from '../types';
import { 
  Server, 
  Globe, 
  Key, 
  ShieldAlert, 
  Terminal, 
  Flame, 
  AlertTriangle,
  Crown,
  Database
} from 'lucide-react';

export type CustomNodeType = Node<{ node: GraphNode; isDimmed?: boolean; isReplayNew?: boolean }, 'customNode'>;

export const CustomGraphNode = memo(({ data, selected }: NodeProps<CustomNodeType>) => {
  const node = data.node;
  const isCritical = node.is_critical;
  const isUndermined = node.undermined;
  const isDimmed = data.isDimmed;
  const isReplayNew = data.isReplayNew;
  const type = node.node_type.toLowerCase();


  // Color scheme and icons by node_type
  let borderColor = 'border-[#cfd6df]/80';
  let badgeBg = 'bg-[#7a8596]/10 text-[#4a5566] border-[#7a8596]/30';
  let iconComponent = <Database className="w-4 h-4 text-[#4a5566] shrink-0" />;
  let typeLabel = node.node_type.toUpperCase();

  if (type.includes('ppp_service') || type === 'service') {
    borderColor = 'border-blue-500/60';
    badgeBg = 'bg-blue-500/15 text-blue-400 border-blue-500/30';
    iconComponent = <Server className="w-4 h-4 text-blue-400 shrink-0" />;
    typeLabel = 'SERVICE';
  } else if (type.includes('endpoint')) {
    borderColor = 'border-teal-500/60';
    badgeBg = 'bg-teal-500/15 text-teal-400 border-teal-500/30';
    iconComponent = <Globe className="w-4 h-4 text-teal-400 shrink-0" />;
    typeLabel = 'ENDPOINT';
  } else if (type.includes('secret') || type.includes('credential')) {
    borderColor = 'border-yellow-500/60';
    badgeBg = 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30';
    iconComponent = <Key className="w-4 h-4 text-yellow-400 shrink-0" />;
    typeLabel = 'SECRET';
  } else if (type.includes('access_control')) {
    borderColor = 'border-rose-500/60';
    badgeBg = 'bg-rose-500/15 text-rose-400 border-rose-500/30';
    iconComponent = <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />;
    typeLabel = 'ACCESS CONTROL';
  } else if (type.includes('reflected_input')) {
    borderColor = 'border-orange-500/60';
    badgeBg = 'bg-orange-500/15 text-orange-400 border-orange-500/30';
    iconComponent = <Terminal className="w-4 h-4 text-orange-400 shrink-0" />;
    typeLabel = 'REFLECTED INPUT';
  } else if (type.includes('finding') || type.includes('vulnerability')) {
    borderColor = 'border-rose-500/60';
    badgeBg = 'bg-rose-500/15 text-rose-400 border-rose-500/30';
    iconComponent = <Flame className="w-4 h-4 text-rose-400 shrink-0" />;
    typeLabel = 'VULNERABILITY';
  }

  // Handle critical styling
  if (isCritical) {
    borderColor = 'border-rose-500';
  }

  // Handle undermined styling
  if (isUndermined && !isCritical) {
    borderColor = 'border-amber-500/80 border-dashed';
  }

  return (
    <div
      className={`relative group transition-opacity duration-200 ${
        isDimmed ? 'opacity-25' : 'opacity-100'
      } ${isCritical ? 'pulse-ring rounded-xl' : ''}`}
    >
      {/* Left target handle for LR layout */}
      <Handle
        type="target"
        position={Position.Left}
        className="!w-2 !h-2 !bg-[#f8f9fb] !border !border-[#7a8596] !left-[-4px]"
      />

      {/* Main Node Card */}
      <div
        className={`w-[220px] h-[72px] p-2.5 rounded-xl bg-[#f8f9fb] border transition-all duration-150 cursor-pointer flex flex-col justify-between select-none hover:-translate-y-0.5 ${borderColor} ${
          isCritical ? 'glow-critical' : ''
        } ${
          selected ? 'ring-2 ring-[#0b7a83] glow-selected border-[#0b7a83]' : 'hover:border-[#4a5566]/50 hover:shadow-lg hover:shadow-black/40'
        } ${isUndermined ? 'opacity-60 bg-[#eceff3]' : ''} ${isReplayNew ? 'replay-pulse' : ''}`}
      >
        {/* Top Header Row: Icon + Label */}
        <div className="flex items-center gap-2 min-w-0">
          <div className="shrink-0">{iconComponent}</div>
          <div 
            className="text-[13px] font-semibold text-[#18202c] truncate flex-1 min-w-0 font-sans"
            title={node.label}
          >
            {node.label}
          </div>
        </div>

        {/* Badges & Flags Row */}
        <div className="flex items-center justify-between gap-1.5 pt-1 border-t border-[#18202c17]">
          <div className="flex items-center gap-1 min-w-0 overflow-hidden">
            <span className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded-md border truncate ${badgeBg}`}>
              {typeLabel}
            </span>

            {isCritical && (
              <span className="inline-flex items-center gap-0.5 text-[10px] font-mono px-1.5 py-0.5 rounded-md bg-rose-500/20 text-rose-400 border border-rose-500/40">
                <Crown className="w-2.5 h-2.5" />
                Critical
              </span>
            )}

            {isUndermined && (
              <span className="inline-flex items-center gap-0.5 text-[10px] font-mono px-1.5 py-0.5 rounded-md bg-amber-500/20 text-amber-400 border border-amber-500/40">
                <AlertTriangle className="w-2.5 h-2.5" />
                Undermined
              </span>
            )}
          </div>

          <span className="text-[11px] font-mono text-[#4a5566] shrink-0">
            #{node.id.slice(0, 6)}
          </span>
        </div>
      </div>

      {/* Right source handle for LR layout */}
      <Handle
        type="source"
        position={Position.Right}
        className="!w-2 !h-2 !bg-[#f8f9fb] !border !border-[#7a8596] !right-[-4px]"
      />
    </div>
  );
});

CustomGraphNode.displayName = 'CustomGraphNode';
