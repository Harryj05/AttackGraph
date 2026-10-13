import React, { useState, useEffect } from 'react';
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

  // Responsive: auto-collapse the sidebar on narrow viewports so the main
  // content never gets pushed off-screen. Manual toggles still work until the
  // next breakpoint crossing. (TraceMap-style breakpoint-driven layout.)
  useEffect(() => {
    const mq = window.matchMedia('(max-width: 1024px)');
    const apply = () => setCollapsed(mq.matches);
    apply();
    mq.addEventListener('change', apply);
    return () => mq.removeEventListener('change', apply);
  }, []);

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
      className={`bg-[#eef1f5] border-r border-[#18202c1f] flex flex-col transition-all duration-200 shrink-0 z-20 ${
        collapsed ? 'w-16' : 'w-56'
      }`}
    >
      {/* Brand Header */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-[#18202c1f]">
        {!collapsed && (
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-[#0b7a83]/30 to-[#0b7a83]/10 border border-[#0b7a83]/40 flex items-center justify-center text-[#0b7a83] shadow-[0_0_12px_-2px_#0b7a83]">
              <Share2 className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-bold tracking-wider uppercase bg-gradient-to-r from-[#18202c] to-[#0b7a83] bg-clip-text text-transparent">
                ATTACKGRAPH AI
              </div>
              <div className="text-[10px] font-mono text-[#0b7a83] flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                SOC v0.1
              </div>
            </div>
          </div>
        )}
        {collapsed && (
          <div className="w-8 h-8 rounded-xl bg-[#0b7a83]/15 border border-[#0b7a83]/40 flex items-center justify-center text-[#0b7a83] mx-auto">
            <Share2 className="w-4 h-4" />
          </div>
        )}

        <button
          onClick={() => setCollapsed(!collapsed)}
          className="text-[#4a5566] hover:text-[#18202c] p-1.5 rounded-lg hover:bg-[#e4e8ee]/50 transition-colors ml-auto cursor-pointer"
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
              className={`relative w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-medium transition-all cursor-pointer ${
                isActive
                  ? 'bg-[#0b7a83]/15 text-[#0b7a83] border border-[#0b7a83]/30 font-semibold shadow-sm'
                  : 'text-[#4a5566] hover:text-[#18202c] hover:bg-[#e4e8ee]/40 border border-transparent hover:translate-x-0.5'
              } ${collapsed ? 'justify-center px-0' : ''}`}
              title={collapsed ? item.label : undefined}
            >
              {isActive && !collapsed && (
                <span className="absolute left-0 top-1/2 -translate-y-1/2 h-5 w-1 rounded-r-full bg-[#0b7a83] shadow-[0_0_8px_#0b7a83]" />
              )}
              <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-[#0b7a83]' : 'text-[#4a5566]'}`} />
              {!collapsed && <span>{item.label}</span>}
            </button>
          );
        })}
      </nav>
    </aside>
  );
};
