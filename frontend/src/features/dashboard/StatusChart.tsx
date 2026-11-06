import { Bar, BarChart, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

/** One series, so one color: the title says what is plotted, and the status names are on the axis. */
const BAR_COLOR = '#2563a8'
const TEXT_COLOR = '#475569'

export interface StatusRow {
  status: string
  label: string
  count: number
}

/** In its own file: Recharts is nearly half of the application, and only this screen needs it. */
export default function StatusChart({ rows }: { rows: StatusRow[] }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 32, bottom: 0, left: 8 }}>
        <XAxis type="number" hide allowDecimals={false} domain={[0, 'dataMax']} />
        <YAxis type="category" dataKey="label" width={72} axisLine={false} tickLine={false} tick={{ fill: TEXT_COLOR, fontSize: 12 }} />
        <Tooltip cursor={{ fill: '#f1f5f9' }} formatter={(value) => [String(value), '件数']} />
        <Bar dataKey="count" fill={BAR_COLOR} barSize={20} radius={[0, 4, 4, 0]} isAnimationActive={false}>
          <LabelList dataKey="count" position="right" fill={TEXT_COLOR} fontSize={12} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
