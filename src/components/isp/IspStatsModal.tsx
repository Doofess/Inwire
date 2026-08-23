import React, { useState, useEffect } from 'react';
import { X, Globe, MapPin, Activity, Server, Database, Shield } from 'lucide-react';

interface IspStatsModalProps {
  isDark: boolean;
  onClose: () => void;
}

interface IspData {
  ip: string;
  network: string;
  version: string;
  city: string;
  region: string;
  region_code: string;
  country: string;
  country_name: string;
  country_code: string;
  country_code_iso3: string;
  country_capital: string;
  country_tld: string;
  continent_code: string;
  in_eu: boolean;
  postal: string;
  latitude: number;
  longitude: number;
  timezone: string;
  utc_offset: string;
  country_calling_code: string;
  currency: string;
  currency_name: string;
  languages: string;
  country_area: number;
  country_population: number;
  asn: string;
  org: string;
}

export const IspStatsModal: React.FC<IspStatsModalProps> = ({ isDark, onClose }) => {
  const [data, setData] = useState<IspData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchIspStats = async () => {
      try {
        const response = await fetch('https://ipapi.co/json/');
        if (!response.ok) {
          throw new Error('Failed to fetch ISP statistics');
        }
        const jsonData = await response.json();
        
        if (jsonData.error) {
          throw new Error(jsonData.reason || 'Failed to fetch ISP statistics');
        }
        
        setData(jsonData);
      } catch (err: any) {
        setError(err.message || 'An error occurred while fetching ISP stats.');
      } finally {
        setLoading(false);
      }
    };

    fetchIspStats();
  }, []);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div 
        className={`w-full max-w-2xl rounded-xl shadow-2xl flex flex-col border ${
          isDark ? 'bg-zinc-950 border-zinc-700 text-zinc-100' : 'bg-white border-zinc-300 text-slate-900'
        }`}
      >
        {/* Header */}
        <div className={`flex items-center justify-between p-4 border-b ${isDark ? 'border-zinc-800' : 'border-slate-200'}`}>
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${isDark ? 'bg-sky-500/20 text-sky-400' : 'bg-sky-100 text-sky-600'}`}>
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h2 className={`font-bold ${isDark ? 'text-zinc-100' : 'text-slate-800'}`}>Local ISP Diagnostics</h2>
              <p className={`text-xs ${isDark ? 'text-zinc-400' : 'text-slate-500'}`}>
                Public WAN Information and Telemetry
              </p>
            </div>
          </div>
          <button onClick={onClose} className={`p-1.5 rounded-md ${isDark ? 'hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200' : 'hover:bg-slate-100 text-slate-500 hover:text-slate-700'}`}>
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-12 gap-4">
              <div className="w-8 h-8 border-4 border-sky-500 border-t-transparent rounded-full animate-spin"></div>
              <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-slate-500'}`}>Probing external network...</p>
            </div>
          ) : error ? (
            <div className={`text-center py-12 px-4 rounded-lg border ${isDark ? 'bg-rose-500/10 border-rose-500/30 text-rose-300' : 'bg-rose-50 border-rose-200 text-rose-600'}`}>
              <Shield className="w-10 h-10 mx-auto mb-3 opacity-80" />
              <p className="font-semibold">{error}</p>
              <p className="text-sm mt-1 opacity-80">Check your internet connection or ad-blocker settings.</p>
            </div>
          ) : data ? (
            <div className="space-y-6">
              
              {/* Primary Info */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className={`p-4 rounded-lg border flex items-start gap-4 ${isDark ? 'bg-zinc-900/50 border-zinc-800' : 'bg-slate-50 border-slate-200'}`}>
                  <Server className={`w-8 h-8 mt-1 shrink-0 ${isDark ? 'text-zinc-400' : 'text-slate-500'}`} />
                  <div className="min-w-0 flex-1">
                    <div className={`text-[11px] uppercase tracking-wider font-semibold mb-1 truncate ${isDark ? 'text-zinc-500' : 'text-slate-500'}`}>
                      Internet Service Provider (ISP)
                    </div>
                    <div className={`font-bold text-lg truncate ${isDark ? 'text-zinc-100' : 'text-slate-800'}`} title={data.org}>{data.org}</div>
                    <div className={`text-sm font-mono mt-1 truncate ${isDark ? 'text-sky-400' : 'text-sky-600'}`}>{data.asn}</div>
                  </div>
                </div>

                <div className={`p-4 rounded-lg border flex items-start gap-4 ${isDark ? 'bg-zinc-900/50 border-zinc-800' : 'bg-slate-50 border-slate-200'}`}>
                  <Database className={`w-8 h-8 mt-1 shrink-0 ${isDark ? 'text-zinc-400' : 'text-slate-500'}`} />
                  <div className="min-w-0 flex-1">
                    <div className={`text-[11px] uppercase tracking-wider font-semibold mb-1 truncate ${isDark ? 'text-zinc-500' : 'text-slate-500'}`}>
                      Public IP Address
                    </div>
                    <div className={`font-bold text-lg break-all ${isDark ? 'text-zinc-100' : 'text-slate-800'}`}>{data.ip}</div>
                    <div className={`text-sm font-mono mt-1 truncate ${isDark ? 'text-emerald-400' : 'text-emerald-600'}`}>IPv{data.version}</div>
                  </div>
                </div>
              </div>

              {/* Secondary Details Table */}
              <div className={`rounded-lg overflow-hidden border ${isDark ? 'border-zinc-800' : 'border-slate-200'}`}>
                <div className={`px-4 py-2 flex items-center gap-2 border-b text-xs font-semibold uppercase tracking-wider ${
                  isDark ? 'bg-zinc-900 border-zinc-800 text-zinc-400' : 'bg-slate-100 border-slate-200 text-slate-600'
                }`}>
                  <MapPin className="w-4 h-4" />
                  Geolocation & Network Telemetry
                </div>
                
                <div className={`divide-y text-sm ${isDark ? 'divide-zinc-800/50 text-zinc-300' : 'divide-slate-200 text-slate-700'}`}>
                  
                  <div className="flex px-4 py-3">
                    <div className={`w-1/3 font-semibold ${isDark ? 'text-zinc-400' : 'text-slate-500'}`}>Location</div>
                    <div className="w-2/3">{data.city}, {data.region}, {data.country_name}</div>
                  </div>
                  
                  <div className="flex px-4 py-3">
                    <div className={`w-1/3 font-semibold ${isDark ? 'text-zinc-400' : 'text-slate-500'}`}>Coordinates</div>
                    <div className="w-2/3 font-mono">{data.latitude}, {data.longitude}</div>
                  </div>
                  
                  <div className="flex px-4 py-3">
                    <div className={`w-1/3 font-semibold ${isDark ? 'text-zinc-400' : 'text-slate-500'}`}>Timezone</div>
                    <div className="w-2/3">{data.timezone} (UTC {data.utc_offset})</div>
                  </div>
                  
                  <div className="flex px-4 py-3">
                    <div className={`w-1/3 font-semibold ${isDark ? 'text-zinc-400' : 'text-slate-500'}`}>Subnet / Block</div>
                    <div className="w-2/3 font-mono">{data.network}</div>
                  </div>

                </div>
              </div>
              
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
};
