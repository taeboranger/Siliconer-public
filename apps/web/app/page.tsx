import Workspace from './workspace';
export const dynamic = 'force-dynamic';
export default function Page() { return <Workspace demo={process.env.SILICONER_DEMO === 'true'} />; }
