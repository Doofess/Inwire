import React, { useMemo } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { Packet } from '../../types/packet';

interface LiveIOGraphProps {
  packets: Packet[];
}

export const LiveIOGraph: React.FC<LiveIOGraphProps> = ({ packets }) => {
  // Aggregate packets by second for the last 60 seconds
  const data = useMemo(() => {
    if (!packets || packets.length === 0) return [];
    
    // Get last timestamp
    const lastTime = new Date(packets[0].timestamp).getTime();
    
    const timeMap = new Map<number, number>();
    
    packets.forEach(p => {
      const pTime = new Date(p.timestamp).getTime();
      const diffSecs = Math.floor((lastTime - pTime) / 1000);
      
      if (diffSecs < 60) {
        const secIndex = 60 - diffSecs;
        timeMap.set(secIndex, (timeMap.get(secIndex) || 0) + 1);
      }
    });

    const chartData = [];
    for (let i = 0; i <= 60; i++) {
      chartData.push({
        time: i,
        packets: timeMap.get(i) || 0,
      });
    }
    
    return chartData;
  }, [packets]);

  const rootStyle = typeof document !== 'undefined' ? getComputedStyle(document.documentElement) : null;
  const popoverColor = rootStyle?.getPropertyValue('--popover').trim() || '#ffffff';
  const borderColor = rootStyle?.getPropertyValue('--border').trim() || '#e2e8f0';

  return (
    <div className="w-full h-full flex flex-col text-card-foreground">
      <div className="px-3 py-1 text-[10px] font-bold uppercase tracking-wider opacity-70 border-b border-inherit border-opacity-10">
        Live I/O (pkts/sec)
      </div>
      <div className="flex-1 min-h-0">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 5, right: 0, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="colorPkts" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
              </linearGradient>
            </defs>
            <YAxis hide domain={['dataMin', 'dataMax + 5']} />
            <Tooltip
              contentStyle={{
                backgroundColor: popoverColor,
                border: `1px solid ${borderColor}`,
                fontSize: '11px',
                padding: '4px 8px'
              }}
              labelFormatter={() => ''}
            />
            <Area 
              type="monotone" 
              dataKey="packets" 
              stroke="#10b981" 
              strokeWidth={1.5}
              fillOpacity={1} 
              fill="url(#colorPkts)" 
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};
