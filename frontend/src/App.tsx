import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import type { Scan, GraphData, GraphNode, GraphEdge, AgentLog, ReplayEvent } from './types';
import { fetchScans, fetchScanGraph, fetchAgentLog, fetchReplayEvents, runAgent } from './api/client';
import { Sidebar } from './components/Sidebar';
import type { NavView } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { StatCards } from './components/StatCards';
import { ActivityLog } from './components/ActivityLog';
import { GraphCanvas } from './components/GraphCanvas';
import { InspectorPanel } from './components/InspectorPanel';
import { ReplayControls } from './components/ReplayControls';
import { CalibrationView } from './components/CalibrationView';
import { AgentView } from './components/AgentView';
import { FindingsView } from './components/FindingsView';
import { ScansView } from './components/ScansView';
import { AlertTriangle, RefreshCw, X, Info } from 'lucide-react';

export function App() {
  const [currentView, setCurrentView] = useState<NavView>('graph');
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>('');
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [agentLogs, setAgentLogs] = useState<AgentLog[]>([]);
  const [showRefuted, setShowRefuted] = useState<boolean>(false);
  const [isRunningAgent, setIsRunningAgent] = useState<boolean>(false);
  const [agentStatusToast, setAgentStatusToast] = useState<string | null>(null);
  const [scanMode, setScanMode] = useState<'agent' | 'deterministic'>('agent');
  const [lastRunMetrics, setLastRunMetrics] = useState<any>(null);

  // Replay Mode State
  const [isReplayMode, setIsReplayMode] = useState<boolean>(false);
  const [replayEvents, setReplayEvents] = useState<ReplayEvent[]>([]);
  const [replayIndex, setReplayIndex] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1);

  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);

  const [loadingScans, setLoadingScans] = useState<boolean>(true);
  const [loadingGraph, setLoadingGraph] = useState<boolean>(false);
  const [loadingLogs, setLoadingLogs] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Polling ref for live agent execution updates
  const pollIntervalRef = useRef<any>(null);

  // Load all scans on mount
  useEffect(() => {
    setLoadingScans(true);
    fetchScans()
      .then((data) => {
        setScans(data);
        if (data.length > 0) {
          setSelectedScanId(data[0].id);
        }
        setLoadingScans(false);
      })
      .catch((err) => {
        console.error('Failed to load scans:', err);
        setErrorMsg('Failed to connect to backend API at http://127.0.0.1:8000.');
        setLoadingScans(false);
      });
  }, []);

  // Fetch Graph Data, Agent Logs, and Replay Events when selectedScanId changes
  const loadScanDetails = useCallback((scanId: string) => {
    if (!scanId) return;

    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }

    setLoadingGraph(true);
    setSelectedNode(null);
    setSelectedEdge(null);

    fetchScanGraph(scanId)
      .then((data) => {
        setGraphData(data);
        setLoadingGraph(false);
      })
      .catch((err) => {
        console.error(`Failed to load graph for scan ${scanId}:`, err);
        setErrorMsg(`Failed to load graph for scan ${scanId}`);
        setLoadingGraph(false);
      });

    setLoadingLogs(true);
    fetchAgentLog(scanId)
      .then((data) => {
        setAgentLogs(data);
        setLoadingLogs(false);
      })
      .catch((err) => {
        console.error(`Failed to load agent log for scan ${scanId}:`, err);
        setLoadingLogs(false);
      });

    fetchReplayEvents(scanId)
      .then((events) => {
        setReplayEvents(events);
        setReplayIndex(events.length > 0 ? events.length - 1 : 0);
      })
      .catch((err) => {
        console.error(`Failed to load replay events for scan ${scanId}:`, err);
      });
  }, []);

  useEffect(() => {
    if (selectedScanId) {
      loadScanDetails(selectedScanId);
    }
  }, [selectedScanId, loadScanDetails]);

  // Clean up polling interval on unmount
  useEffect(() => {
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, []);

  // Handle View navigation changes
  const handleSelectView = (view: NavView) => {
    setCurrentView(view);
    if (view === 'replay') {
      setIsReplayMode(true);
      if (replayEvents.length > 0) {
        setReplayIndex(0);
      }
    } else {
      setIsReplayMode(false);
      setIsPlaying(false);
    }
  };

  // Handle Playback Timer in Replay Mode with Speed support
  useEffect(() => {
    let timer: any = null;
    const intervalMs = Math.round(1000 / playbackSpeed);

    if (isPlaying && isReplayMode && replayEvents.length > 0) {
      timer = setInterval(() => {
        setReplayIndex((prev) => {
          if (prev >= replayEvents.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, intervalMs);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [isPlaying, isReplayMode, replayEvents, playbackSpeed]);

  // Refetch graph when human review or reverify occurs
  const handleRefetchGraph = useCallback(() => {
    if (selectedScanId) {
      fetchScanGraph(selectedScanId)
        .then((data) => setGraphData(data))
        .catch((err) => console.error('Error refetching graph:', err));

      fetchReplayEvents(selectedScanId)
        .then((events) => setReplayEvents(events))
        .catch((err) => console.error('Error refetching replay events:', err));
    }
  }, [selectedScanId]);

  // Active step number for two-way ActivityLog sync
  const activeStepNumber = useMemo(() => {
    if (!isReplayMode || replayEvents.length === 0) return null;
    const currentEv = replayEvents[replayIndex];
    return currentEv?.step_number ?? null;
  }, [isReplayMode, replayEvents, replayIndex]);

  // Handle clicking a step in ActivityLog sidebar to jump replay position
  const handleSelectStepFromLog = useCallback((stepNumber: number) => {
    if (!isReplayMode) return;
    const targetIdx = replayEvents.findIndex((ev) => ev.step_number === stepNumber);
    if (targetIdx !== -1) {
      setReplayIndex(targetIdx);
    } else {
      setAgentStatusToast(`Step #${stepNumber} has no associated graph replay events.`);
    }
  }, [isReplayMode, replayEvents]);


  // Handle clicking step badge in Agent timeline to jump to Replay view
  const handleSelectStepForReplay = useCallback((stepNumber: number) => {
    setCurrentView('replay');
    setIsReplayMode(true);
    const targetIdx = replayEvents.findIndex((ev) => ev.step_number === stepNumber);
    if (targetIdx !== -1) {
      setReplayIndex(targetIdx);
    } else {
      setReplayIndex(0);
    }
  }, [replayEvents]);

  // Live Run Agent Execution with 3s Polling
  const handleRunAgent = async () => {
    if (!selectedScanId || isRunningAgent) return;
    const targetScanId = selectedScanId;

    setIsRunningAgent(true);
    setAgentStatusToast(null);

    // Start 3s polling for live graph & log updates
    pollIntervalRef.current = setInterval(() => {
      fetchScanGraph(targetScanId)
        .then((data) => {
          setGraphData((prev) => (prev?.scan_id === targetScanId || !prev ? data : prev));
        })
        .catch(() => {});
      fetchAgentLog(targetScanId)
        .then((logs) => setAgentLogs(logs))
        .catch(() => {});
    }, 3000);

    try {
      const runRes = await runAgent(targetScanId, 15, scanMode);
      if (runRes && runRes.metrics) {
        setLastRunMetrics(runRes.metrics);
      }
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
      setIsRunningAgent(false);
      loadScanDetails(targetScanId);
    } catch (err: any) {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
      setIsRunningAgent(false);
      setAgentStatusToast("Agent stopped early. Progress so far is saved.");
      loadScanDetails(targetScanId);
    }
  };


  const [isActivityLogOpen, setIsActivityLogOpen] = useState<boolean>(false);

  const handleScanCreated = (newScan: Scan) => {
    setScans((prev) => [newScan, ...prev]);
    setSelectedScanId(newScan.id);
    setCurrentView('graph');
  };

  const showStatCards = (currentView === 'graph' || currentView === 'findings') && !isReplayMode;

  if (loadingScans) {
    return (
      <div className="h-screen w-screen bg-[#eef1f5] flex flex-col items-center justify-center text-xs font-mono text-[#4a5566] gap-3">
        <RefreshCw className="w-6 h-6 animate-spin text-[#0b7a83]" />
        <span>INITIALIZING ATTACKGRAPH AI SOC FRONTEND...</span>
      </div>
    );
  }

  return (
    <div className="h-screen w-screen bg-[#eef1f5] flex flex-row overflow-hidden font-sans text-[#18202c]">
      {/* 1. Left Sidebar Navigation */}
      <Sidebar currentView={currentView} onSelectView={handleSelectView} />

      {/* Main Content Layout Container */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Error Alert Bar */}
        {errorMsg && (
          <div className="bg-rose-500/15 border-b border-rose-500/30 text-rose-400 px-4 py-2 text-xs font-mono flex items-center justify-between shrink-0">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
            <button
              onClick={() => setErrorMsg(null)}
              className="text-xs hover:underline cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Dismissible Agent Status Toast Bar */}
        {agentStatusToast && (
          <div className="bg-amber-500/15 border-b border-amber-500/30 text-amber-300 px-4 py-2 text-xs font-mono flex items-center justify-between shrink-0 animate-in fade-in duration-200">
            <div className="flex items-center gap-2">
              <Info className="w-4 h-4 text-amber-400 shrink-0" />
              <span>{agentStatusToast}</span>
            </div>
            <button
              onClick={() => setAgentStatusToast(null)}
              className="text-amber-400 hover:text-amber-200 p-0.5 rounded cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* 2. Top Navigation Bar */}
        <TopBar
          scans={scans}
          selectedScanId={selectedScanId}
          onSelectScan={setSelectedScanId}
          onRunAgent={handleRunAgent}
          isRunningAgent={isRunningAgent}
          onOpenCalibration={() => handleSelectView('calibration')}
          onScanCreated={handleScanCreated}
        />

        {/* 3. Stat Cards Row (Visible on Graph, Findings, Replay) */}
        {showStatCards && <StatCards graphData={graphData} />}

        {/* View Content Area */}
        <div className="flex-1 flex flex-row overflow-hidden relative min-h-0">
          {currentView === 'agent' ? (
            <AgentView
              agentLogs={agentLogs}
              loading={loadingLogs}
              onSelectStepForReplay={handleSelectStepForReplay}
              scanMode={scanMode}
              onChangeScanMode={setScanMode}
              onRunScan={handleRunAgent}
              isRunningScan={isRunningAgent}
              lastRunMetrics={lastRunMetrics}
            />
          ) : currentView === 'findings' ? (
            <FindingsView
              scanId={selectedScanId}
              nodes={graphData?.nodes || []}
              edges={graphData?.edges || []}
              onSelectFindingNode={(node) => {
                setSelectedNode(node);
                setSelectedEdge(null);
                setCurrentView('graph');
              }}
            />
          ) : currentView === 'scans' ? (
            <ScansView
              scans={scans}
              selectedScanId={selectedScanId}
              onSelectScan={setSelectedScanId}
              onNavigateToGraph={() => setCurrentView('graph')}
              graphData={graphData}
            />
          ) : currentView === 'calibration' ? (
            <CalibrationView
              scans={scans}
              onClose={() => handleSelectView('graph')}
            />
          ) : (
            /* Graph & Replay Views */
            <>
              {/* Left Drawer / Log (for Graph & Replay) */}
              <ActivityLog
                logs={agentLogs}
                loading={loadingLogs}
                activeStepNumber={activeStepNumber}
                onSelectStep={handleSelectStepFromLog}
                isOpen={isActivityLogOpen}
                onToggle={() => setIsActivityLogOpen((prev) => !prev)}
              />

              {/* Main Graph View */}
              <main className="flex-1 flex flex-col relative h-full overflow-hidden">
                {loadingGraph && (
                  <div className="absolute inset-0 bg-[#eef1f5]/80 z-30 flex items-center justify-center text-xs font-mono text-[#0b7a83] gap-2">
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Rendering Scan Graph...</span>
                  </div>
                )}

                <div className="flex-1 relative">
                  <GraphCanvas
                    graphData={graphData}
                    showRefuted={showRefuted}
                    onToggleShowRefuted={() => setShowRefuted((prev) => !prev)}
                    selectedNodeId={selectedNode?.id}
                    selectedEdgeId={selectedEdge?.id}
                    onSelectNode={setSelectedNode}
                    onSelectEdge={setSelectedEdge}
                    isReplayMode={isReplayMode}
                    replayEvents={replayEvents}
                    replayIndex={replayIndex}
                    isActivityLogOpen={isActivityLogOpen}
                    onToggleActivityLog={() => setIsActivityLogOpen((prev) => !prev)}
                  />
                </div>

                {/* Replay Controls (Bottom bar) */}
                {isReplayMode && (
                  <ReplayControls
                    events={replayEvents}
                    currentIndex={replayIndex}
                    isPlaying={isPlaying}
                    onIndexChange={setReplayIndex}
                    onPlayPause={() => setIsPlaying((prev) => !prev)}
                    onReset={() => {
                      setReplayIndex(0);
                      setIsPlaying(false);
                    }}
                    speed={playbackSpeed}
                    onSpeedChange={setPlaybackSpeed}
                  />
                )}
              </main>

              {/* Right Inspector Panel */}
              <InspectorPanel
                scanId={selectedScanId}
                selectedScan={scans.find((s) => s.id === selectedScanId)}
                selectedNode={selectedNode}
                selectedEdge={selectedEdge}
                nodes={graphData?.nodes || []}
                edges={graphData?.edges || []}
                onSelectNode={setSelectedNode}
                onSelectEdge={setSelectedEdge}
                onRefetchGraph={handleRefetchGraph}
              />
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
