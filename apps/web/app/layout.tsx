import type { Metadata } from 'next';
import './style.css';
export const metadata: Metadata = { title: 'Siliconer · 배포 보안 검토', description: '실제 배포 자산과 보안 권고문의 연결 근거를 확인합니다.', robots: { index: false, follow: false } };
export default function Layout({ children }: { children: React.ReactNode }) {
  return <html lang="ko"><body>{children}</body></html>;
}
