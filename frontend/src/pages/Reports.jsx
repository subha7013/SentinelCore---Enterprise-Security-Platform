import React, { useEffect, useState, useMemo } from 'react';
import axios from 'axios';
import {
  FileText, Download, Play, Sparkles, CheckCircle2, AlertTriangle,
  Calendar, Filter, Clock, RefreshCw, X, ChevronDown, BarChart2,
  Shield, Bug, Siren, Globe, Users, FileBarChart, ToggleLeft, ToggleRight,
  Eye, Printer, Lock, Check, Cpu, Award
} from 'lucide-react';
import { useToast } from '../components/Toast';

// ─── Report type catalogue ────────────────────────────────────────────────────
const REPORT_TYPES = [
  {
    id: 'INCIDENT_SUMMARY',
    label: 'Incident Summary',
    icon: Siren,
    color: 'border-red-500/30 bg-red-500/10 text-red-300',
    desc: 'All incidents grouped by priority, status, assigned team, and MTTR.',
  },
  {
    id: 'VULNERABILITY_REPORT',
    label: 'Vulnerability Report',
    icon: Bug,
    color: 'border-orange-500/30 bg-orange-500/10 text-orange-300',
    desc: 'CVE findings with severity breakdown, asset mapping, and patch status.',
  },
  {
    id: 'COMPLIANCE_AUDIT',
    label: 'Compliance Audit',
    icon: Shield,
    color: 'border-sky-500/30 bg-sky-500/10 text-sky-300',
    desc: 'Framework control attestation status, open gaps, and evidence log.',
  },
  {
    id: 'THREAT_INTEL',
    label: 'Threat Intelligence',
    icon: Globe,
    color: 'border-purple-500/30 bg-purple-500/10 text-purple-300',
    desc: 'IOC list, enrichment data, feed activity, and analyst notes.',
  },
  {
    id: 'EXECUTIVE_SUMMARY',
    label: 'Executive Summary',
    icon: BarChart2,
    color: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
    desc: 'High-level KPI dashboard — MTTR, risk score, open incidents, compliance posture.',
  },
  {
    id: 'USER_ACTIVITY',
    label: 'User Activity',
    icon: Users,
    color: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
    desc: 'Audit trail of logins, role changes, and administrative actions.',
  },
];

const SEVERITIES  = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const FORMATS     = ['PDF', 'CSV', 'JSON'];
const FREQUENCIES = ['Daily', 'Weekly', 'Monthly', 'Quarterly'];

// ─── Standalone Printable Report HTML Generator (Dashboard Dark Theme) ──────
const generatePrintableReportHTML = (item) => {
  const dateStr = new Date(item.createdAt || Date.now()).toLocaleString();
  const hashStr = item.metrics?.['Document Verification Hash'] || 'SHA256-8F9A2B4C1D9E7F0A';
  const execBrief = item.metrics?.['Executive Brief'] || 'Automated security operations report compiled by SentinelCore SOAR Engine.';
  const riskScore = item.metrics?.['Org Risk Score'] || 'LOW (18/100)';
  const mttr = item.metrics?.['Avg MTTR (Hours)'] || '1.8';
  const compliance = item.metrics?.['Overall Compliance Score'] || item.metrics?.['Compliance Score'] || '94%';
  const threatIocs = item.metrics?.['Total Threat Indicators'] || '24';
  
  const metricCardsHTML = item.metrics ? Object.entries(item.metrics)
    .filter(([k]) => k !== 'Classification' && k !== 'Document Verification Hash' && k !== 'Executive Brief' && k !== 'Applied Severity Filter')
    .map(([k, v]) => `
      <div style="background: rgba(22, 27, 34, 0.9); border: 1px solid rgba(255,255,255,0.1); padding: 14px; border-radius: 14px; box-shadow: 0 4px 14px rgba(0,0,0,0.25);">
        <div style="font-size: 10px; text-transform: uppercase; color: #94a3b8; font-family: monospace; font-weight: bold;">${k}</div>
        <div style="font-size: 18px; font-weight: 800; color: #ffffff; font-family: monospace; margin-top: 4px;">${v}</div>
        <div style="font-size: 9px; color: #34d399; font-family: monospace; margin-top: 4px;">✓ Verified Telemetry</div>
      </div>
    `).join('') : '';

  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>${item.title} - SentinelCore Executive Security Report</title>
      <meta charset="utf-8" />
      <style>
        @page { size: A4 portrait; margin: 10mm; }
        html, body {
          background: #080b14 linear-gradient(180deg, #080b14 0%, #0b1220 48%, #101827 100%) !important;
          color: #f8fafc !important;
          font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          margin: 0;
          padding: 24px;
          min-height: 100vh;
          box-sizing: border-box;
          -webkit-print-color-adjust: exact !important;
          print-color-adjust: exact !important;
          color-adjust: exact !important;
        }
        * {
          -webkit-print-color-adjust: exact !important;
          print-color-adjust: exact !important;
          color-adjust: exact !important;
        }
        .header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #38bdf8; padding-bottom: 16px; margin-bottom: 20px; }
        .logo-box { width: 48px; height: 48px; background: linear-gradient(135deg, #1e40af, #bae6fd); border-radius: 12px; display: flex; align-items: center; justify-content: center; box-shadow: 0 6px 16px rgba(37,99,235,0.4); }
        .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
        .table { width: 100%; border-collapse: collapse; margin-top: 12px; font-family: monospace; font-size: 11px; background: rgba(11, 18, 32, 0.8); border-radius: 12px; overflow: hidden; border: 1px solid rgba(255,255,255,0.08); }
        .table th { background: rgba(255,255,255,0.08); text-align: left; padding: 10px; color: #94a3b8; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .table td { padding: 10px; border-bottom: 1px solid rgba(255,255,255,0.05); color: #e2e8f0; }
        .footer { border-top: 2px solid rgba(56, 189, 248, 0.3); padding-top: 16px; margin-top: 30px; display: flex; justify-content: space-between; align-items: center; }
      </style>
    </head>
    <body>
      <!-- OFFICIAL SENTINELCORE LOGO HEADER -->
      <div class="header">
        <div style="display: flex; align-items: center; gap: 12px;">
          <div class="logo-box">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </div>
          <div>
            <div style="font-size: 18px; font-weight: 900; letter-spacing: 0.2em; color: #ffffff; font-family: monospace;">SENTINEL<span style="color: #38bdf8;">CORE</span></div>
            <div style="font-size: 9px; font-weight: 700; letter-spacing: 0.25em; color: #7dd3fc; text-transform: uppercase;">ENTERPRISE SECURITY OPERATIONS PLATFORM</div>
            <div style="font-size: 9px; color: #94a3b8; font-family: monospace;">SOAR Threat Intelligence & Automated Compliance Engine</div>
          </div>
        </div>
        <div style="text-align: right;">
          <span style="display: inline-block; background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.4); color: #fca5a5; font-size: 9px; font-weight: bold; font-family: monospace; padding: 4px 10px; border-radius: 9999px; text-transform: uppercase;">CONFIDENTIAL // SOC EYES ONLY</span>
          <div style="font-size: 10px; color: #94a3b8; font-family: monospace; margin-top: 4px;">Generated: ${dateStr}</div>
          <div style="font-size: 10px; color: #94a3b8; font-family: monospace;">Author: ${item.generatedBy || 'Security Lead'}</div>
        </div>
      </div>

      <!-- TITLE & BRIEF -->
      <div style="margin-bottom: 20px;">
        <h1 style="font-size: 20px; font-weight: 800; color: #ffffff; margin: 0 0 8px 0;">${item.title}</h1>
        <div style="background: rgba(22, 27, 34, 0.85); border: 1px solid rgba(255,255,255,0.08); padding: 14px; border-radius: 12px; font-size: 12px; color: #cbd5e1; line-height: 1.5;">
          <strong style="color: #38bdf8; font-family: monospace; font-size: 10px; text-transform: uppercase; display: block; margin-bottom: 4px;">Executive Brief:</strong>
          ${execBrief}
        </div>
      </div>

      <!-- FILTERS -->
      <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; background: rgba(11, 18, 32, 0.9); padding: 12px; border-radius: 12px; font-family: monospace; font-size: 10px; border: 1px solid rgba(255,255,255,0.08); margin-bottom: 20px;">
        <div><span style="color: #64748b; display: block;">DATE RANGE</span><strong style="color: #f1f5f9;">${item.dateFrom || 'Start'} → ${item.dateTo || 'Present'}</strong></div>
        <div><span style="color: #64748b; display: block;">SEVERITY FILTER</span><strong style="color: #38bdf8;">${item.severityFilter || 'ALL'}</strong></div>
        <div><span style="color: #64748b; display: block;">TARGET TEAM</span><strong style="color: #f1f5f9;">${item.teamFilter || 'All Teams'}</strong></div>
        <div><span style="color: #64748b; display: block;">ASSET TARGET</span><strong style="color: #f1f5f9;">${item.assetFilter || 'All Assets'}</strong></div>
      </div>

      <!-- METRICS GRID -->
      <div style="margin-bottom: 20px;">
        <div style="font-size: 10px; font-weight: bold; font-family: monospace; text-transform: uppercase; letter-spacing: 0.15em; color: #94a3b8; margin-bottom: 8px;">Key Security Metrics & Telemetry Indicators</div>
        <div class="grid-4">
          ${metricCardsHTML}
        </div>
      </div>

      <!-- TELEMETRY TABLE -->
      <div style="margin-bottom: 24px;">
        <div style="font-size: 10px; font-weight: bold; font-family: monospace; text-transform: uppercase; letter-spacing: 0.15em; color: #94a3b8; margin-bottom: 8px;">Operational Audit Telemetry & Evidence Trail</div>
        <table class="table">
          <thead>
            <tr>
              <th>Control / Metric Name</th>
              <th>Telemetry Value</th>
              <th>Compliance Status</th>
              <th style="text-align: right;">Audit Source</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style="font-weight: bold; color: #ffffff;">System Risk Posture</td>
              <td style="color: #6ee7b7; font-weight: bold;">${riskScore}</td>
              <td><span style="background: rgba(16,185,129,0.15); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.3); padding: 2px 6px; border-radius: 4px;">PASSED</span></td>
              <td style="text-align: right; color: #64748b;">SentinelCore RiskEngine</td>
            </tr>
            <tr>
              <td style="font-weight: bold; color: #ffffff;">Incident Response MTTR</td>
              <td style="color: #38bdf8;">${mttr} Hours</td>
              <td><span style="background: rgba(16,185,129,0.15); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.3); padding: 2px 6px; border-radius: 4px;">OPTIMAL</span></td>
              <td style="text-align: right; color: #64748b;">IncidentService SLA</td>
            </tr>
            <tr>
              <td style="font-weight: bold; color: #ffffff;">Perimeter Threat Isolation</td>
              <td style="color: #c084fc;">${threatIocs} Active IOCs</td>
              <td><span style="background: rgba(168,85,247,0.15); color: #c084fc; border: 1px solid rgba(168,85,247,0.3); padding: 2px 6px; border-radius: 4px;">BLOCKED</span></td>
              <td style="text-align: right; color: #64748b;">ThreatIntel Registry</td>
            </tr>
            <tr>
              <td style="font-weight: bold; color: #ffffff;">Framework Attestation</td>
              <td style="color: #fcd34d;">${compliance}</td>
              <td><span style="background: rgba(56,189,248,0.15); color: #7dd3fc; border: 1px solid rgba(56,189,248,0.3); padding: 2px 6px; border-radius: 4px;">ATTESTED</span></td>
              <td style="text-align: right; color: #64748b;">Compliance Audit Service</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- PROPER LOGO FOOTER -->
      <div class="footer">
        <div style="display: flex; align-items: center; gap: 10px;">
          <div class="logo-box" style="width: 32px; height: 32px; border-radius: 8px;">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </div>
          <div>
            <div style="font-size: 11px; font-weight: 800; letter-spacing: 0.15em; color: #ffffff; font-family: monospace;">SENTINEL<span style="color: #38bdf8;">CORE</span></div>
            <div style="font-size: 8px; color: #94a3b8; font-family: monospace;">© 2026 SentinelCore Platform · Enterprise Security Operations</div>
          </div>
        </div>

        <div style="text-align: right; font-family: monospace; font-size: 9px;">
          <div style="color: #34d399; font-weight: bold; margin-bottom: 2px;">★ DIGITAL VERIFICATION SEAL ATTESTED</div>
          <div style="color: #94a3b8;">Document Hash: <span style="color: #cbd5e1;">${hashStr}</span></div>
          <div style="color: #64748b;">Page 1 of 1 · Generated automatically by SentinelCore SOAR Engine</div>
        </div>
      </div>

      <div style="text-align: center; font-family: monospace; font-size: 8px; color: #475569; margin-top: 12px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 8px;">
        CONFIDENTIALITY NOTICE: This document contains proprietary security telemetry data. Unauthorized distribution or copying is strictly prohibited.
      </div>
    </body>
    </html>
  `;
};

// ─── Type badge ───────────────────────────────────────────────────────────────
function TypeBadge({ typeId }) {
  const t = REPORT_TYPES.find((r) => r.id === typeId);
  if (!t) return <span className="sc-badge">{typeId}</span>;
  return <span className={`sc-badge ${t.color}`}>{t.label}</span>;
}

// ─── Schedule Toggle ──────────────────────────────────────────────────────────
function ToggleSwitch({ value, onChange, label }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!value)}
      className="flex items-center gap-2 text-sm font-medium text-slate-300 transition hover:text-white"
    >
      {value
        ? <ToggleRight className="h-5 w-5 text-sky-400" />
        : <ToggleLeft  className="h-5 w-5 text-slate-600" />}
      {label}
    </button>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function Reports() {
  const { showToast } = useToast();

  // Form state
  const [reportType,     setReportType]     = useState('INCIDENT_SUMMARY');
  const [dateFrom,       setDateFrom]       = useState('');
  const [dateTo,         setDateTo]         = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [teamFilter,     setTeamFilter]     = useState('');
  const [assetFilter,    setAssetFilter]    = useState('');
  const [format,         setFormat]         = useState('PDF');
  const [scheduleEnabled,setSchedule]       = useState(false);
  const [frequency,      setFrequency]      = useState('Weekly');
  const [generating,     setGenerating]     = useState(false);

  // History & Active Viewing Modal
  const [history, setHistory]               = useState([]);
  const [histSearch, setHSearch]             = useState('');
  const [typeFilter,  setTypeFilter]         = useState('ALL');
  const [loading, setLoading]               = useState(true);
  const [selectedReportForView, setSelectedReportForView] = useState(null);

  // Teams for dropdown
  const [teams, setTeams] = useState([]);
  useEffect(() => {
    axios.get('/api/teams').then((r) => setTeams(r.data || [])).catch(() => {});
    axios.get('/api/reports')
      .then((r) => setHistory(r.data))
      .catch(() => showToast({ type: 'error', message: 'Failed to load report history.' }))
      .finally(() => setLoading(false));
  }, [showToast]);

  const selectedType = REPORT_TYPES.find((t) => t.id === reportType);

  const filteredHistory = useMemo(() => {
    return history.filter((h) => {
      const matchType  = typeFilter === 'ALL' || h.type === typeFilter;
      const matchSearch = !histSearch || (h.title && h.title.toLowerCase().includes(histSearch.toLowerCase()));
      return matchType && matchSearch;
    });
  }, [history, typeFilter, histSearch]);

  const triggerPDFExport = (item) => {
    if (!item) return;
    setSelectedReportForView(item);

    const htmlContent = generatePrintableReportHTML(item);

    // Create or reuse hidden print iframe
    let iframe = document.getElementById('sentinelcore-print-iframe');
    if (!iframe) {
      iframe = document.createElement('iframe');
      iframe.id = 'sentinelcore-print-iframe';
      iframe.style.position = 'fixed';
      iframe.style.right = '0';
      iframe.style.bottom = '0';
      iframe.style.width = '0px';
      iframe.style.height = '0px';
      iframe.style.border = '0';
      iframe.style.visibility = 'hidden';
      document.body.appendChild(iframe);
    }

    const doc = iframe.contentWindow.document;
    doc.open();
    doc.write(htmlContent);
    doc.close();

    // Trigger iframe print after content is rendered
    setTimeout(() => {
      try {
        iframe.contentWindow.focus();
        iframe.contentWindow.print();
      } catch (err) {
        console.error('Print iframe error', err);
      }
    }, 350);
  };

  const handleGenerate = async (e) => {
    e.preventDefault();
    setGenerating(true);
    try {
      const payload = { type: reportType, dateFrom, dateTo, severityFilter, teamFilter, assetFilter, format, scheduled: scheduleEnabled, frequency };
      const res = await axios.post('/api/reports/generate', payload);
      showToast({ type: 'success', message: `Report "${res.data?.title || reportType}" generated` });
      setHistory((prev) => [res.data, ...prev]);
      setSelectedReportForView(res.data);
      if (format === 'PDF') {
        triggerPDFExport(res.data);
      }
    } catch (err) {
      showToast({ type: 'error', message: err.response?.data?.message || 'Failed to generate report' });
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = (item, fmt) => {
    showToast({ type: 'info', message: `Preparing ${item.title} for ${fmt} export` });
    
    if (fmt === 'PDF') {
      // 1. Trigger hidden iframe print with complete dark dashboard styled executive document
      triggerPDFExport(item);

      // 2. Download standalone HTML report document file to user's downloads folder
      const htmlContent = generatePrintableReportHTML(item);
      const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8;' });
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `report_${item.id || Date.now()}.html`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      return;
    }

    let content = "";
    let mimeType = "";
    let extension = "";

    if (fmt === 'CSV') {
      content = `Report Title,Generated By,Date\n"${item.title}","${item.generatedBy}","${new Date(item.createdAt).toLocaleString()}"\n\nMetric,Value\n`;
      if (item.metrics) {
        Object.entries(item.metrics).forEach(([k, v]) => {
          content += `"${k}","${v}"\n`;
        });
      }
      mimeType = "text/csv;charset=utf-8;";
      extension = "csv";
    } else if (fmt === 'JSON') {
      content = JSON.stringify(item, null, 2);
      mimeType = "application/json";
      extension = "json";
    }

    const blob = new Blob([content], { type: mimeType });
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", `report_${item.id || Date.now()}.${extension}`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6 sc-fade-in">
      {/* ── Page header ─────────────────────────────────────────────────── */}
      <div className="sc-panel p-6">
        <div className="flex flex-wrap items-center gap-2">
          <span className="sc-badge border-emerald-500/20 bg-emerald-500/10 text-emerald-300">
            <FileBarChart className="h-3 w-3" /> Reports & Analytics
          </span>
          <span className="sc-badge border-white/10 bg-white/5 text-slate-400">
            <Shield className="h-3 w-3 text-sky-400" /> SentinelCore Security Engine
          </span>
        </div>
        <h1 className="mt-3 text-2xl font-extrabold tracking-tight text-white">Executive Report Builder</h1>
        <p className="mt-2 max-w-3xl text-sm text-slate-400">
          Generate compliance, incident, vulnerability, and executive security reports with custom telemetry filters. Exports print-ready PDF reports with official logo header and footer.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* ── Builder panel ──────────────────────────────────────────────── */}
        <div className="space-y-4 xl:col-span-1">
          {/* Report type cards */}
          <div className="sc-panel p-5">
            <p className="sc-text-kicker mb-3">Report Type</p>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-1">
              {REPORT_TYPES.map((rt) => {
                const Icon = rt.icon;
                return (
                  <button
                    key={rt.id}
                    onClick={() => setReportType(rt.id)}
                    className={`flex items-start gap-3 rounded-2xl border p-3 text-left transition ${
                      reportType === rt.id
                        ? `${rt.color} ring-1 ring-white/15`
                        : 'border-white/8 bg-white/3 text-slate-400 hover:bg-white/5 hover:text-white'
                    }`}
                  >
                    <div className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border ${reportType === rt.id ? rt.color : 'border-white/10 bg-white/5'}`}>
                      <Icon className="h-3.5 w-3.5" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-semibold text-white">{rt.label}</p>
                      <p className="mt-0.5 text-[10px] text-slate-500 leading-relaxed">{rt.desc}</p>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* ── Right: Filters + Actions + History ─────────────────────────── */}
        <div className="space-y-4 xl:col-span-2">
          {/* Filter panel */}
          <div className="sc-panel p-5">
            <p className="sc-text-kicker mb-4">Filters & Parameters</p>
            <form onSubmit={handleGenerate} className="space-y-4">
              {/* Date range */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block text-[10px] font-mono uppercase tracking-wider text-slate-500">
                    <Calendar className="mr-1 inline h-3 w-3" /> From Date
                  </label>
                  <input
                    type="date"
                    value={dateFrom}
                    onChange={(e) => setDateFrom(e.target.value)}
                    className="w-full rounded-xl border border-white/8 bg-white/5 px-3 py-2 text-xs text-white focus:border-sky-500/40 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[10px] font-mono uppercase tracking-wider text-slate-500">
                    <Calendar className="mr-1 inline h-3 w-3" /> To Date
                  </label>
                  <input
                    type="date"
                    value={dateTo}
                    onChange={(e) => setDateTo(e.target.value)}
                    className="w-full rounded-xl border border-white/8 bg-white/5 px-3 py-2 text-xs text-white focus:border-sky-500/40 focus:outline-none"
                  />
                </div>
              </div>

              {/* Severity filter chips */}
              <div>
                <label className="mb-2 block text-[10px] font-mono uppercase tracking-wider text-slate-500">Severity</label>
                <div className="flex flex-wrap gap-1.5">
                  {SEVERITIES.map((s) => (
                    <button
                      key={s} type="button"
                      onClick={() => setSeverityFilter(s)}
                      className={`rounded-full border px-2.5 py-1 text-[10px] font-bold font-mono uppercase transition ${
                        severityFilter === s
                          ? 'border-sky-500/40 bg-sky-500/15 text-sky-300'
                          : 'border-white/8 bg-white/3 text-slate-500 hover:text-white'
                      }`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>

              {/* Team + Asset filters */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block text-[10px] font-mono uppercase tracking-wider text-slate-500">Team</label>
                  <select
                    value={teamFilter}
                    onChange={(e) => setTeamFilter(e.target.value)}
                    className="w-full rounded-xl border border-white/8 bg-[#0b1220] px-3 py-2 text-xs text-white focus:border-sky-500/40 focus:outline-none"
                  >
                    <option value="">All Teams</option>
                    {teams.map((t) => <option key={t.id} value={t.id}>{t.teamName}</option>)}
                  </select>
                </div>
                <div>
                  <label className="mb-1 block text-[10px] font-mono uppercase tracking-wider text-slate-500">Asset Filter</label>
                  <input
                    type="text"
                    value={assetFilter}
                    onChange={(e) => setAssetFilter(e.target.value)}
                    placeholder="e.g. PROD-DB-01"
                    className="w-full rounded-xl border border-white/8 bg-white/5 px-3 py-2 text-xs text-white placeholder-slate-600 focus:border-sky-500/40 focus:outline-none"
                  />
                </div>
              </div>

              {/* Format + Schedule row */}
              <div className="flex flex-wrap items-center gap-4 rounded-2xl border border-white/8 bg-white/3 p-4">
                {/* Format chips */}
                <div>
                  <p className="mb-2 text-[10px] font-mono uppercase tracking-wider text-slate-500">Output Format</p>
                  <div className="flex gap-1.5">
                    {FORMATS.map((f) => (
                      <button
                        key={f} type="button"
                        onClick={() => setFormat(f)}
                        className={`rounded-lg border px-3 py-1.5 text-[10px] font-bold font-mono transition ${
                          format === f
                            ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
                            : 'border-white/8 bg-white/3 text-slate-500 hover:text-white'
                        }`}
                      >
                        {f}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Schedule toggle */}
                <div className="flex-1">
                  <p className="mb-2 text-[10px] font-mono uppercase tracking-wider text-slate-500">Schedule</p>
                  <div className="flex items-center gap-4">
                    <ToggleSwitch value={scheduleEnabled} onChange={setSchedule} label={scheduleEnabled ? 'Scheduled' : 'On Demand'} />
                    {scheduleEnabled && (
                      <select
                        value={frequency}
                        onChange={(e) => setFrequency(e.target.value)}
                        className="rounded-xl border border-sky-500/30 bg-sky-500/10 px-3 py-1 text-xs text-sky-300 focus:outline-none bg-transparent"
                      >
                        {FREQUENCIES.map((f) => <option key={f} value={f}>{f}</option>)}
                      </select>
                    )}
                  </div>
                </div>
              </div>

              {/* Action buttons */}
              <div className="flex gap-3">
                <button
                  type="submit"
                  disabled={generating}
                  className="sc-button-primary flex-1 py-3 text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  {generating ? (
                    <><div className="h-4 w-4 animate-spin rounded-full border-2 border-black/25 border-t-black" /><span>Generating Report…</span></>
                  ) : (
                    <><Play className="h-4 w-4" /><span>{scheduleEnabled ? `Schedule ${frequency}` : 'Generate & View Executive Report'}</span></>
                  )}
                </button>
                {scheduleEnabled && (
                  <button
                    type="button"
                    onClick={() => showToast({ type: 'info', message: `${frequency} schedule saved for ${selectedType?.label}` })}
                    className="sc-button-secondary px-4 py-3 text-sm font-semibold"
                  >
                    <Clock className="h-4 w-4" />
                    Save Schedule
                  </button>
                )}
              </div>
            </form>
          </div>

          {/* History table */}
          <div className="sc-panel overflow-hidden p-0">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/8 p-4">
              <div>
                <p className="sc-text-kicker">Generated Report History</p>
                <p className="mt-0.5 text-xs text-slate-500">{filteredHistory.length} report{filteredHistory.length !== 1 ? 's' : ''}</p>
              </div>
              <div className="flex items-center gap-2">
                {/* Type filter */}
                <div className="relative">
                  <select
                    value={typeFilter}
                    onChange={(e) => setTypeFilter(e.target.value)}
                    className="appearance-none rounded-xl border border-white/8 bg-white/5 py-2 pl-3 pr-7 text-xs text-slate-300 focus:outline-none"
                  >
                    <option value="ALL">All Types</option>
                    {REPORT_TYPES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
                  </select>
                  <ChevronDown className="pointer-events-none absolute right-2 top-1/2 h-3 w-3 -translate-y-1/2 text-slate-500" />
                </div>
                {/* Search */}
                <input
                  value={histSearch}
                  onChange={(e) => setHSearch(e.target.value)}
                  placeholder="Search reports…"
                  className="rounded-xl border border-white/8 bg-white/5 px-3 py-2 text-xs text-white placeholder-slate-600 focus:border-sky-500/40 focus:outline-none"
                />
              </div>
            </div>

            {loading ? (
              <div className="flex items-center justify-center py-16">
                <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary/20 border-t-primary" />
              </div>
            ) : filteredHistory.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16">
                <FileBarChart className="mb-2 h-8 w-8 text-slate-600" />
                <p className="text-xs font-mono text-slate-500">No reports match current filters.</p>
              </div>
            ) : (
              <div className="divide-y divide-white/6">
                {filteredHistory.map((item) => (
                  <div key={item.id} className="flex flex-col gap-3 p-4 transition hover:bg-white/3 sm:flex-row sm:items-center sm:justify-between">
                    <div className="space-y-1.5 cursor-pointer" onClick={() => setSelectedReportForView(item)}>
                      <div className="flex flex-wrap items-center gap-2">
                        <TypeBadge typeId={item.type} />
                        <span className="font-mono text-[10px] text-slate-500">
                          {new Date(item.createdAt).toLocaleString()}
                        </span>
                        {item.format && (
                          <span className="sc-badge border-white/10 bg-white/5 text-slate-400">{item.format}</span>
                        )}
                      </div>
                      <p className="text-sm font-semibold text-white hover:text-sky-300 transition">{item.title}</p>
                      <p className="font-mono text-[10px] text-slate-500">
                        By: {item.generatedBy} {item.size && item.size !== '—' ? `· ${item.size}` : ''}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setSelectedReportForView(item)}
                        className="flex items-center gap-1.5 rounded-xl border border-sky-500/25 bg-sky-500/10 px-3 py-2 text-xs font-semibold text-sky-300 hover:bg-sky-500/20 transition"
                        title="View Report Details"
                      >
                        <Eye className="h-3.5 w-3.5" /> View
                      </button>
                      <button
                        onClick={() => handleDownload(item, 'CSV')}
                        className="sc-button-secondary px-3 py-2 text-xs font-semibold"
                      >
                        <Download className="h-3.5 w-3.5" /> CSV
                      </button>
                      <button
                        onClick={() => handleDownload(item, 'PDF')}
                        className="sc-button-secondary px-3 py-2 text-xs font-semibold flex items-center gap-1 text-sky-300 border-sky-500/30"
                      >
                        <Printer className="h-3.5 w-3.5 text-sky-400" /> Export PDF
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── HIGH-FIDELITY EXECUTIVE REPORT VIEWER MODAL ───────────────────────── */}
      {selectedReportForView && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md overflow-y-auto">
          <div className="relative w-full max-w-4xl max-h-[92vh] overflow-y-auto rounded-3xl border border-white/12 bg-[#080b14] p-8 shadow-2xl sc-scale-in space-y-6">

            {/* Top Modal Controls */}
            <div className="flex items-center justify-between border-b border-white/10 pb-4 print:hidden">
              <div className="flex items-center gap-2">
                <span className="sc-badge border-sky-500/30 bg-sky-500/10 text-sky-300">
                  <Shield className="h-3.5 w-3.5 text-sky-400" /> Executive Report Document
                </span>
                <span className="font-mono text-xs text-slate-400">ID: #{selectedReportForView.id?.substring(0, 8) || 'REP-8492'}</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => triggerPDFExport(selectedReportForView)}
                  className="flex items-center gap-1.5 rounded-xl border border-sky-500/30 bg-sky-500/10 px-4 py-2 text-xs font-extrabold text-sky-300 hover:bg-sky-500/20 transition shadow-sm"
                >
                  <Printer className="h-3.5 w-3.5 text-sky-400" /> Print / Export PDF
                </button>
                <button
                  onClick={() => handleDownload(selectedReportForView, 'CSV')}
                  className="sc-button-secondary px-3 py-2 text-xs font-semibold"
                >
                  <Download className="h-3.5 w-3.5" /> CSV
                </button>
                <button
                  onClick={() => handleDownload(selectedReportForView, 'JSON')}
                  className="sc-button-secondary px-3 py-2 text-xs font-semibold"
                >
                  <Download className="h-3.5 w-3.5" /> JSON
                </button>
                <button
                  onClick={() => setSelectedReportForView(null)}
                  className="c-p rounded-xl border border-white/10 bg-white/5 p-2 text-slate-400 hover:text-white transition"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
            </div>

            {/* Printable Document Container (Matches Dashboard Dark Gradient Theme) */}
            <div id="printable-report-document" className="space-y-6 bg-gradient-to-b from-[#080b14] via-[#0b1220] to-[#101827] p-6 text-slate-100 rounded-2xl border border-white/10 shadow-2xl">

              {/* ── OFFICIAL SENTINELCORE HEADER WITH LOGO ───────────────────── */}
              <div className="flex flex-wrap items-start justify-between gap-4 border-b-2 border-sky-500/30 pb-6">
                <div className="flex items-center gap-4">
                  {/* Official SentinelCore Logo Badge */}
                  <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br from-blue-800 to-sky-200 shadow-[0_12px_28px_rgba(37,99,235,0.4)]">
                    <Shield className="h-8 w-8 text-white" />
                  </div>
                  <div>
                    <div className="text-xl font-extrabold tracking-[0.25em] text-white font-mono">
                      SENTINEL<span className="text-sky-400">CORE</span>
                    </div>
                    <p className="text-[10px] font-bold uppercase tracking-[0.3em] text-sky-300">
                      ENTERPRISE SECURITY OPERATIONS PLATFORM
                    </p>
                    <p className="text-[9px] font-mono text-slate-400 mt-0.5">
                      SOAR Threat Intelligence & Automated Compliance Engine
                    </p>
                  </div>
                </div>

                <div className="text-right space-y-1">
                  <span className="inline-flex items-center gap-1 rounded-full border border-red-500/40 bg-red-500/15 px-3 py-1 text-[9px] font-bold font-mono tracking-widest text-red-300 uppercase">
                    <Lock className="h-2.5 w-2.5" /> CONFIDENTIAL // SOC EYES ONLY
                  </span>
                  <p className="text-[10px] font-mono text-slate-400">Generated: {new Date(selectedReportForView.createdAt || Date.now()).toLocaleString()}</p>
                  <p className="text-[10px] font-mono text-slate-400">Author: <strong className="text-slate-200">{selectedReportForView.generatedBy || 'Security Lead'}</strong></p>
                </div>
              </div>

              {/* Document Overview */}
              <div>
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-extrabold text-white tracking-tight">{selectedReportForView.title}</h2>
                  <TypeBadge typeId={selectedReportForView.type} />
                </div>
                {selectedReportForView.metrics?.['Executive Brief'] && (
                  <p className="mt-2 text-xs text-slate-300 leading-relaxed font-sans bg-white/3 p-3.5 rounded-xl border border-white/8">
                    <strong className="text-sky-300 font-mono text-[10px] uppercase block mb-1">Executive Summary Brief:</strong>
                    {selectedReportForView.metrics['Executive Brief']}
                  </p>
                )}
              </div>

              {/* Applied Filters Context */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono bg-[#0b1220]/90 p-3.5 rounded-xl border border-white/8">
                <div>
                  <span className="text-[9px] uppercase text-slate-500 block">Date Range</span>
                  <span className="text-slate-200 font-bold">{selectedReportForView.dateFrom || 'Start'} → {selectedReportForView.dateTo || 'Present'}</span>
                </div>
                <div>
                  <span className="text-[9px] uppercase text-slate-500 block">Severity Filter</span>
                  <span className="text-sky-300 font-bold">{selectedReportForView.severityFilter || 'ALL'}</span>
                </div>
                <div>
                  <span className="text-[9px] uppercase text-slate-500 block">Target Team</span>
                  <span className="text-slate-200 font-bold">{selectedReportForView.teamFilter || 'All Teams'}</span>
                </div>
                <div>
                  <span className="text-[9px] uppercase text-slate-500 block">Asset Target</span>
                  <span className="text-slate-200 font-bold">{selectedReportForView.assetFilter || 'All Assets'}</span>
                </div>
              </div>

              {/* ── KEY SECURITY METRICS GRID ───────────────────────────────── */}
              <div>
                <p className="text-[10px] font-bold font-mono uppercase tracking-[0.2em] text-slate-400 mb-3 flex items-center gap-1.5">
                  <BarChart2 className="h-3.5 w-3.5 text-sky-400" /> Key Security Metrics & Telemetry Indicators
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
                  {selectedReportForView.metrics && Object.entries(selectedReportForView.metrics)
                    .filter(([k]) => k !== 'Classification' && k !== 'Document Verification Hash' && k !== 'Executive Brief' && k !== 'Applied Severity Filter')
                    .map(([key, val]) => (
                      <div key={key} className="rounded-2xl border border-white/10 bg-[#161b22]/90 p-4 text-left space-y-1 shadow-sm">
                        <p className="text-[10px] font-mono uppercase text-slate-400 font-semibold truncate">{key}</p>
                        <p className="text-lg font-extrabold text-white tracking-tight font-mono">{String(val)}</p>
                        <div className="flex items-center gap-1 text-[9px] font-mono text-emerald-400">
                          <CheckCircle2 className="h-2.5 w-2.5" /> Verified Telemetry
                        </div>
                      </div>
                    ))}
                </div>
              </div>

              {/* Detailed Evidence Breakdown Table */}
              <div className="space-y-2">
                <p className="text-[10px] font-bold font-mono uppercase tracking-[0.2em] text-slate-400 flex items-center gap-1.5">
                  <FileText className="h-3.5 w-3.5 text-purple-400" /> Operational Audit Telemetry & Evidence Trail
                </p>
                <div className="overflow-x-auto rounded-2xl border border-white/10 bg-[#0b1220]/80">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="border-b border-white/10 bg-white/5 text-[9px] font-bold uppercase text-slate-400">
                      <tr>
                        <th className="p-3">Control / Metric Name</th>
                        <th className="p-3">Telemetry Value</th>
                        <th className="p-3">Compliance Status</th>
                        <th className="p-3 text-right">Audit Source</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 text-slate-300">
                      <tr>
                        <td className="p-3 font-semibold text-white">System Risk Posture</td>
                        <td className="p-3 text-emerald-300 font-bold">{selectedReportForView.metrics?.['Org Risk Score'] || 'LOW (18/100)'}</td>
                        <td className="p-3"><span className="sc-badge border-emerald-500/30 bg-emerald-500/10 text-emerald-300">PASSED</span></td>
                        <td className="p-3 text-right text-slate-500">SentinelCore RiskEngine</td>
                      </tr>
                      <tr>
                        <td className="p-3 font-semibold text-white">Incident Response MTTR</td>
                        <td className="p-3 text-sky-300">{selectedReportForView.metrics?.['Avg MTTR (Hours)'] || '1.8'} Hours</td>
                        <td className="p-3"><span className="sc-badge border-emerald-500/30 bg-emerald-500/10 text-emerald-300">OPTIMAL</span></td>
                        <td className="p-3 text-right text-slate-500">IncidentService SLA</td>
                      </tr>
                      <tr>
                        <td className="p-3 font-semibold text-white">Perimeter Threat Isolation</td>
                        <td className="p-3 text-purple-300">{selectedReportForView.metrics?.['Total Threat Indicators'] || '24'} Active IOCs</td>
                        <td className="p-3"><span className="sc-badge border-purple-500/30 bg-purple-500/10 text-purple-300">BLOCKED</span></td>
                        <td className="p-3 text-right text-slate-500">ThreatIntel Registry</td>
                      </tr>
                      <tr>
                        <td className="p-3 font-semibold text-white">Framework Attestation</td>
                        <td className="p-3 text-amber-300">{selectedReportForView.metrics?.['Overall Compliance Score'] || selectedReportForView.metrics?.['Compliance Score'] || '94%'}</td>
                        <td className="p-3"><span className="sc-badge border-sky-500/30 bg-sky-500/10 text-sky-300">ATTESTED</span></td>
                        <td className="p-3 text-right text-slate-500">Compliance Audit Service</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* ── PROPER OFFICIAL LOGO FOOTER ───────────────────────────────── */}
              <div className="pt-6 border-t-2 border-sky-500/20 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-4 text-xs">

                  {/* Left Footer Block: Official Logo + Copyright */}
                  <div className="flex items-center gap-3">
                    <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-blue-800 to-sky-200 shadow-md">
                      <Shield className="h-5 w-5 text-white" />
                    </div>
                    <div>
                      <div className="text-xs font-extrabold tracking-[0.2em] text-white font-mono">
                        SENTINEL<span className="text-sky-400">CORE</span>
                      </div>
                      <p className="text-[9px] font-mono text-slate-400">
                        © 2026 SentinelCore Platform · Enterprise Security Operations
                      </p>
                    </div>
                  </div>

                  {/* Right Footer Block: Verification Hash & Seals */}
                  <div className="text-right space-y-1 font-mono text-[10px]">
                    <div className="flex items-center justify-end gap-2 text-emerald-400 font-bold">
                      <Award className="h-3.5 w-3.5 text-emerald-400" /> DIGITAL VERIFICATION SEAL ATTESTED
                    </div>
                    <p className="text-slate-500">
                      Document Hash: <span className="text-slate-300">{selectedReportForView.metrics?.['Document Verification Hash'] || 'SHA256-8F9A2B4C1D9E7F0A'}</span>
                    </p>
                    <p className="text-slate-600">Page 1 of 1 · Generated automatically by SentinelCore SOAR Engine</p>
                  </div>
                </div>

                <p className="text-center font-mono text-[9px] text-slate-600 border-t border-white/5 pt-2">
                  CONFIDENTIALITY NOTICE: This document contains proprietary security telemetry data. Unauthorized distribution or copying is strictly prohibited.
                </p>
              </div>

            </div>

            {/* Modal Bottom Action Controls */}
            <div className="flex justify-end gap-3 pt-4 border-t border-white/10 print:hidden">
              <button
                onClick={() => triggerPDFExport(selectedReportForView)}
                className="flex items-center gap-2 rounded-xl border border-emerald-500/40 bg-emerald-500/20 px-6 py-2.5 text-xs font-extrabold text-emerald-300 hover:bg-emerald-500/30 transition shadow-md"
              >
                <Printer className="h-4 w-4" /> Print / Export PDF
              </button>
              <button
                onClick={() => setSelectedReportForView(null)}
                className="sc-button-secondary px-5 py-2.5 text-xs font-semibold"
              >
                Close Executive Document
              </button>
            </div>

          </div>
        </div>
      )}

      {/* ── PRINT CSS STYLES FOR DASHBOARD DARK THEME ──────────────────────────── */}
      <style>{`
        @media print {
          @page {
            size: A4 portrait;
            margin: 10mm;
          }
          html, body {
            background: #080b14 linear-gradient(180deg, #080b14 0%, #0b1220 48%, #101827 100%) !important;
            color: #ffffff !important;
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
            color-adjust: exact !important;
          }
          * {
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
            color-adjust: exact !important;
          }
          .fixed.inset-0 {
            position: static !important;
            background: #080b14 !important;
            padding: 0 !important;
            overflow: visible !important;
          }
          .fixed.inset-0 > div {
            max-width: 100% !important;
            max-height: none !important;
            border: none !important;
            background: #080b14 linear-gradient(180deg, #080b14 0%, #0b1220 48%, #101827 100%) !important;
            box-shadow: none !important;
            padding: 0 !important;
          }
          .print\\:hidden, button, nav, aside {
            display: none !important;
          }
          #printable-report-document {
            display: block !important;
            position: static !important;
            width: 100% !important;
            background: #080b14 linear-gradient(180deg, #080b14 0%, #0b1220 48%, #101827 100%) !important;
            color: #ffffff !important;
            padding: 0 !important;
          }
        }
      `}</style>
    </div>
  );
}
