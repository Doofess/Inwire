import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { TbX, TbGlobe, TbMapPin, TbServer, TbDatabase, TbShield } from 'react-icons/tb';
import { modalBackdropMotion, modalPanelMotion } from '../../lib/modalMotion';

interface IspStatsModalProps {
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

export const IspStatsModal: React.FC<IspStatsModalProps> = ({ onClose }) => {
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
    <motion.div
      {...modalBackdropMotion}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
    >
      <motion.div
        {...modalPanelMotion}
        className="w-full max-w-2xl rounded-xl shadow-2xl flex flex-col border bg-card border-border text-card-foreground"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-sky-500/20">
              <TbGlobe className="w-5 h-5 text-foreground" />
            </div>
            <div>
              <h2 className="font-bold text-foreground">Local ISP Diagnostics</h2>
              <p className="text-xs text-muted-foreground">
                Public WAN Information and Telemetry
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-md hover:bg-accent text-muted-foreground hover:text-foreground">
            <TbX className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-12 gap-4">
              <div className="w-8 h-8 border-4 border-sky-500 border-t-transparent rounded-full animate-spin"></div>
              <p className="text-sm text-muted-foreground">Probing external network...</p>
            </div>
          ) : error ? (
            <div className="text-center py-12 px-4 rounded-lg border bg-rose-50 dark:bg-rose-500/10 border-rose-200 dark:border-rose-500/30 text-rose-700 dark:text-rose-300">
              <TbShield className="w-10 h-10 mx-auto mb-3 opacity-80" />
              <p className="font-semibold">{error}</p>
              <p className="text-sm mt-1 opacity-80">Check your internet connection or ad-blocker settings.</p>
            </div>
          ) : data ? (
            <div className="space-y-6">

              {/* Primary Info */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-4 rounded-lg border flex items-start gap-4 bg-muted/50 border-border">
                  <TbServer className="w-8 h-8 mt-1 shrink-0 text-muted-foreground" />
                  <div className="min-w-0 flex-1">
                    <div className="text-[11px] uppercase tracking-wider font-semibold mb-1 truncate text-muted-foreground">
                      Internet Service Provider (ISP)
                    </div>
                    <div className="font-bold text-lg truncate text-foreground" title={data.org}>{data.org}</div>
                    <div className="text-sm font-mono mt-1 truncate text-sky-600 dark:text-sky-400">{data.asn}</div>
                  </div>
                </div>

                <div className="p-4 rounded-lg border flex items-start gap-4 bg-muted/50 border-border">
                  <TbDatabase className="w-8 h-8 mt-1 shrink-0 text-muted-foreground" />
                  <div className="min-w-0 flex-1">
                    <div className="text-[11px] uppercase tracking-wider font-semibold mb-1 truncate text-muted-foreground">
                      Public IP Address
                    </div>
                    <div className="font-bold text-lg break-all text-foreground">{data.ip}</div>
                    <div className="text-sm font-mono mt-1 truncate text-emerald-600 dark:text-emerald-400">IPv{data.version}</div>
                  </div>
                </div>
              </div>

              {/* Secondary Details Table */}
              <div className="rounded-lg overflow-hidden border border-border">
                <div className="px-4 py-2 flex items-center gap-2 border-b text-xs font-semibold uppercase tracking-wider bg-secondary border-border text-muted-foreground">
                  <TbMapPin className="w-4 h-4" />
                  Geolocation & Network Telemetry
                </div>

                <div className="divide-y text-sm divide-border text-foreground/80">

                  <div className="flex px-4 py-3">
                    <div className="w-1/3 font-semibold text-muted-foreground">Location</div>
                    <div className="w-2/3">{data.city}, {data.region}, {data.country_name}</div>
                  </div>

                  <div className="flex px-4 py-3">
                    <div className="w-1/3 font-semibold text-muted-foreground">Coordinates</div>
                    <div className="w-2/3 font-mono">{data.latitude}, {data.longitude}</div>
                  </div>

                  <div className="flex px-4 py-3">
                    <div className="w-1/3 font-semibold text-muted-foreground">Timezone</div>
                    <div className="w-2/3">{data.timezone} (UTC {data.utc_offset})</div>
                  </div>

                  <div className="flex px-4 py-3">
                    <div className="w-1/3 font-semibold text-muted-foreground">Subnet / Block</div>
                    <div className="w-2/3 font-mono">{data.network}</div>
                  </div>

                </div>
              </div>

            </div>
          ) : null}
        </div>
      </motion.div>
    </motion.div>
  );
};
