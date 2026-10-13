import React, { useState, useEffect } from 'react';
import type { Scan, CalibrationReport } from '../types';
import { fetchGlobalCalibration, fetchScanCalibration } from '../api/client';
import { BarChart3, AlertTriangle, RefreshCw, HelpCircle } from 'lucide-react';


interface CalibrationViewProps {
  scans: Scan[];
  onClose: () => void;
}

export const CalibrationView: React.FC<CalibrationViewProps> = ({ scans }) => {
  const [scope, setScope] = useState<'global' | string>('global');
  const [report, setReport] = useState<CalibrationReport | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);

    const promise = scope === 'global'
      ? fetchGlobalCalibration()
      : fetchScanCalibration(scope);

    promise
      .then((data) => {
        setReport(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error('Calibration fetch error:', err);
        setError(`Failed to load calibration report: ${err.message}`);
        setLoading(false);
      });
  }, [scope]);

  return (
    <div className="flex-1 bg-[#eef1f5] flex flex-col overflow-y-auto p-6 space-y-6 select-none font-sans text-[#18202c]">
      {/* 1. Header & Scope Selector */}
      <div className="bg-[#f8f9fb] border border-[#18202c1f] rounded-2xl p-5 flex flex-wrap items-center justify-between gap-4 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400">
            <BarChart3 className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-[#18202c] flex items-center gap-2 uppercase tracking-wider">
              Offline Calibration & Evaluation
            </h2>
            <p className="text-xs text-[#4a5566] font-sans">
              Comparing stated confidence estimates against empirical ground-truth verification outcomes
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="bg-[#eef1f5] border border-[#18202c1f] px-3.5 py-1.5 rounded-xl flex items-center gap-2">
            <span className="text-xs font-mono text-[#4a5566]">Scope:</span>
            <select
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              className="bg-[#f8f9fb] text-[#18202c] text-xs font-mono border border-[#18202c1f] rounded-lg px-2.5 py-1 cursor-pointer focus:outline-none focus:border-[#0b7a83]"
            >
              <option value="global">All Scans (Global Aggregated)</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  Scan #{s.id.slice(0, 8)} ({s.target_url})
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* 2. ALWAYS-Visible Sample Size Warning Banner */}
      <div className="bg-amber-500/15 border-2 border-amber-500/40 rounded-2xl p-4 flex items-start gap-3 shadow-xl">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="flex-1 space-y-1">
          <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400 font-mono">
            STATISTICAL SAMPLE SIZE WARNING
          </h4>
          <p className="text-xs font-mono text-[#18202c] leading-relaxed">
            {report?.sample_size_warning || "WARNING: Evaluated sample size N < 30 edges. Calibration statistics (ECE, Brier, reliability diagram) are preliminary observations."}
          </p>
        </div>
      </div>

      {loading ? (
        <div className="flex-1 flex flex-col items-center justify-center py-20 text-xs font-mono text-amber-400 gap-3">
          <RefreshCw className="w-6 h-6 animate-spin" />
          <span>Computing Calibration Metrics & Reliability Diagram...</span>
        </div>
      ) : error ? (
        <div className="bg-rose-500/15 border border-rose-500/30 text-rose-400 p-4 rounded-2xl font-mono text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      ) : report ? (
        <>


          {/* 3. Headline Metrics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-[#f8f9fb] border border-[#18202c1f] p-4 rounded-2xl flex flex-col justify-between shadow-xl">
              <span className="text-[11px] font-mono uppercase text-[#4a5566] flex items-center justify-between">
                <span>Expected Calibration Error (ECE)</span>
                <HelpCircle className="w-3.5 h-3.5 text-[#7a8596]" />
              </span>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-amber-400">
                  {report.ece !== null ? report.ece.toFixed(4) : 'N/A'}
                </span>
                {report.ece !== null && (
                  <span className="text-xs font-mono text-[#4a5566]">
                    ({(report.ece * 100).toFixed(1)}%)
                  </span>
                )}
              </div>
              <span className="text-[10px] text-[#4a5566] mt-2 leading-relaxed">
                ECE measures how closely stated edge confidences match empirical accuracy rates across buckets.
              </span>
            </div>

            <div className="bg-[#f8f9fb] border border-[#18202c1f] p-4 rounded-2xl flex flex-col justify-between shadow-xl">
              <span className="text-[11px] font-mono uppercase text-[#4a5566] flex items-center justify-between">
                <span>Brier Score</span>
                <HelpCircle className="w-3.5 h-3.5 text-[#7a8596]" />
              </span>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-emerald-400">
                  {report.brier_score !== null ? report.brier_score.toFixed(4) : 'N/A'}
                </span>
              </div>
              <span className="text-[10px] text-[#4a5566] mt-2 leading-relaxed">
                Brier score is the mean squared error of probabilistic predictions (0.0 represents perfect calibration).
              </span>
            </div>

            <div className="bg-[#f8f9fb] border border-[#18202c1f] p-4 rounded-2xl flex flex-col justify-between shadow-xl">
              <span className="text-[11px] font-mono uppercase text-[#4a5566]">Evaluated Edges</span>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-[#18202c]">
                  {report.total_edges_with_outcome}
                </span>
              </div>
              <span className="text-[10px] font-mono text-emerald-400 mt-2">
                Has ground truth outcome (verified or refuted)
              </span>
            </div>

            <div className="bg-[#f8f9fb] border border-[#18202c1f] p-4 rounded-2xl flex flex-col justify-between shadow-xl">
              <span className="text-[11px] font-mono uppercase text-[#4a5566]">Unverified Excluded</span>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-[#4a5566]">
                  {report.total_edges_unverified_excluded}
                </span>
              </div>
              <span className="text-[10px] font-mono text-[#7a8596] mt-2">
                Awaiting resolution before calibration calculation
              </span>
            </div>
          </div>

          {/* 4. Reliability Diagram SVG + Bucket Table */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Reliability Diagram Card */}
            <div className="bg-[#f8f9fb] border border-[#18202c1f] rounded-2xl p-5 space-y-4 shadow-xl flex flex-col">
              <div className="flex items-center justify-between border-b border-[#18202c17] pb-3">
                <h3 className="text-xs font-bold uppercase tracking-wider text-[#18202c] font-mono">
                  Reliability Diagram
                </h3>
                <span className="text-[10px] font-mono text-[#4a5566]">Y = Observed vs X = Stated</span>
              </div>

              <div className="flex-1 flex flex-col items-center justify-center relative py-4">
                <svg className="w-64 h-64 overflow-visible" viewBox="0 0 200 200">
                  {/* Grid Lines */}
                  <line x1="0" y1="0" x2="200" y2="0" stroke="rgba(255,255,255,0.08)" strokeDasharray="4 4" />
                  <line x1="0" y1="50" x2="200" y2="50" stroke="rgba(255,255,255,0.08)" strokeDasharray="4 4" />
                  <line x1="0" y1="100" x2="200" y2="100" stroke="rgba(255,255,255,0.08)" strokeDasharray="4 4" />
                  <line x1="0" y1="150" x2="200" y2="150" stroke="rgba(255,255,255,0.08)" strokeDasharray="4 4" />
                  <line x1="0" y1="200" x2="200" y2="200" stroke="rgba(255,255,255,0.08)" />

                  <line x1="0" y1="0" x2="0" y2="200" stroke="rgba(255,255,255,0.08)" />
                  <line x1="50" y1="0" x2="50" y2="200" stroke="rgba(255,255,255,0.08)" strokeDasharray="4 4" />
                  <line x1="100" y1="0" x2="100" y2="200" stroke="rgba(255,255,255,0.08)" strokeDasharray="4 4" />
                  <line x1="150" y1="0" x2="150" y2="200" stroke="rgba(255,255,255,0.08)" strokeDasharray="4 4" />
                  <line x1="200" y1="0" x2="200" y2="200" stroke="rgba(255,255,255,0.08)" />

                  {/* Diagonal Ideal Line (y = x) */}
                  <line x1="0" y1="200" x2="200" y2="0" stroke="#0b7a83" strokeWidth="2" strokeDasharray="6 6" />

                  {/* Data Points & Connecting Line */}
                  {(() => {
                    const validPoints = report.buckets
                      .filter((b) => b.count > 0 && b.mean_stated_confidence !== null && b.observed_rate !== null)
                      .map((b) => ({
                        x: (b.mean_stated_confidence || 0) * 200,
                        y: 200 - (b.observed_rate || 0) * 200,
                      }));

                    if (validPoints.length === 0) return null;

                    const polylinePoints = validPoints.map((p) => `${p.x},${p.y}`).join(' ');

                    return (
                      <>
                        <polyline points={polylinePoints} fill="none" stroke="#22C55E" strokeWidth="2.5" />
                        {validPoints.map((p, idx) => (
                          <circle key={idx} cx={p.x} cy={p.y} r="5" fill="#22C55E" stroke="#eef1f5" strokeWidth="2" />
                        ))}
                      </>
                    );
                  })()}
                </svg>
              </div>

              <div className="flex items-center justify-between text-[11px] font-mono text-[#4a5566] pt-2 border-t border-[#18202c17]">
                <div className="flex items-center gap-1.5">
                  <span className="w-3 h-0.5 border-b-2 border-dashed border-[#0b7a83]" />
                  <span>Ideal Calibration</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="w-3 h-0.5 bg-emerald-400" />
                  <span>Observed Performance</span>
                </div>
              </div>
            </div>

            {/* 5-Bucket Range Calibration Details Table */}
            <div className="lg:col-span-2 bg-[#f8f9fb] border border-[#18202c1f] rounded-2xl p-5 space-y-4 shadow-xl">
              <div className="flex items-center justify-between border-b border-[#18202c17] pb-3">
                <h3 className="text-xs font-bold uppercase tracking-wider text-[#18202c] font-mono flex items-center gap-2">
                  Confidence Range Bucket Analysis
                </h3>
                <span className="text-[11px] font-mono text-[#4a5566]">5 Calibration Buckets</span>
              </div>

              <div className="space-y-3">
                {report.buckets.map((b) => {
                  const hasData = b.count > 0;
                  const statedPct = b.mean_stated_confidence !== null ? b.mean_stated_confidence * 100 : 0;
                  const obsPct = b.observed_rate !== null ? b.observed_rate * 100 : 0;

                  return (
                    <div
                      key={b.range}
                      className="bg-[#eef1f5] border border-[#18202c1f] rounded-xl p-3.5 font-mono text-xs space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <span className="bg-[#0b7a83]/15 text-[#0b7a83] font-bold px-2.5 py-0.5 rounded-md border border-[#0b7a83]/30">
                            Range {b.range}
                          </span>
                          <span className="text-[#4a5566]">
                            Sample Count: <strong className="text-[#18202c]">{b.count}</strong>
                          </span>
                        </div>

                        {hasData ? (
                          <div className="flex items-center gap-4 text-xs">
                            <span>
                              Stated: <strong className="text-amber-400">{statedPct.toFixed(1)}%</strong>
                            </span>
                            <span>
                              Observed: <strong className="text-emerald-400">{obsPct.toFixed(1)}%</strong>
                            </span>
                          </div>
                        ) : (
                          <span className="text-[#7a8596] italic text-[11px] px-2.5 py-0.5 rounded bg-[#f8f9fb] border border-[#18202c12]">
                            no data in this range
                          </span>
                        )}
                      </div>

                      {/* Bar Comparisons */}
                      {hasData ? (
                        <div className="space-y-1.5 pt-1">
                          <div className="flex items-center gap-3">
                            <span className="w-24 text-[10px] text-[#4a5566] text-right shrink-0">Stated Conf</span>
                            <div className="flex-1 bg-[#f8f9fb] h-2.5 rounded-full overflow-hidden border border-[#18202c12]">
                              <div
                                className="bg-amber-400 h-full transition-all duration-500 rounded-full"
                                style={{ width: `${statedPct}%` }}
                              />
                            </div>
                            <span className="w-10 text-[10px] text-amber-400 font-bold">{statedPct.toFixed(0)}%</span>
                          </div>

                          <div className="flex items-center gap-3">
                            <span className="w-24 text-[10px] text-[#4a5566] text-right shrink-0">Observed Rate</span>
                            <div className="flex-1 bg-[#f8f9fb] h-2.5 rounded-full overflow-hidden border border-[#18202c12]">
                              <div
                                className="bg-emerald-400 h-full transition-all duration-500 rounded-full"
                                style={{ width: `${obsPct}%` }}
                              />
                            </div>
                            <span className="w-10 text-[10px] text-emerald-400 font-bold">{obsPct.toFixed(0)}%</span>
                          </div>
                        </div>
                      ) : (
                        <div className="h-6 bg-[#f8f9fb] rounded-lg border border-[#18202c12] flex items-center justify-center text-[10px] text-[#7a8596]">
                          Bucket is empty - no edges fell into range {b.range}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
};
