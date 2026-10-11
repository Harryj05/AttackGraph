import React, { useState } from 'react';
import { 
  Share2, 
  Bot, 
  ShieldAlert, 
  PlayCircle, 
  BarChart3, 
  FolderKanban,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';

export type NavView = 'graph' | 'agent' | 'findings' | 'replay' | 'calibration' | 'scans';

interface SidebarProps {
  currentView: NavView;
  onSelectView: (view: NavView) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentView, onSelectView }) => {
  const [collapsed, setCollapsed] = useState(false);

  const navItems = [
    { id: 'graph' as NavView, label: 'Graph', icon: Share2 },
    { id: 'agent' as NavView, label: 'Agent', icon: Bot },
    { id: 'findings' as NavView, label: 'Findings', icon: ShieldAlert },
    { id: 'replay' as NavView, label: 'Replay', icon: PlayCircle },
    { id: 'calibration' as NavView, label: 'Calibration', icon: BarChart3 },
    { id: 'scans' as NavView, label: 'Scans', icon: FolderKanban },
  ];

  return (
    <aside 
      className={`bg-[#0B0D1A] border-r border-[#ffffff14] flex flex-col transition-all duration-200 shrink-0 z-20 ${
        collapsed ? 'w-16' : 'w-56'
      }`}
    >
      {/* Brand Header */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-[#ffffff14]">
        {!collapsed && (
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-[#6366F1]/15 border border-[#6366F1]/40 flex items-center justify-center text-[#6366F1]">
              <Share2 className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-bold tracking-wider text-slate-100 uppercase">
                ATTACKGRAPH AI
              </div>
              <div className="text-[10px] font-mono text-indigo-400">SOC v0.1</div>
            </div>
          </div>
        )}
        {collapsed && (
          <div className="w-8 h-8 rounded-xl bg-[#6366F1]/15 border border-[#6366F1]/40 flex items-center justify-center text-[#6366F1] mx-auto">
            <Share2 className="w-4 h-4" />
          </div>
        )}

        <button
          onClick={() => setCollapsed(!collapsed)}
          className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800/50 transition-colors ml-auto cursor-pointer"
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >

          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* Navigation List */}
      <nav className="flex-1 py-4 px-2 space-y-1.5 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectView(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-medium transition-all cursor-pointer ${
                isActive
                  ? 'bg-[#6366F1]/15 text-[#6366F1] border border-[#6366F1]/30 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
              } ${collapsed ? 'justify-center px-0' : ''}`}
              title={collapsed ? item.label : undefined}
            >
              <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-[#6366F1]' : 'text-slate-400'}`} />
              {!collapsed && <span>{item.label}</span>}
            </button>
          );
        })}
      </nav>
    </aside>
  );
};
