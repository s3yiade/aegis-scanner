import TopNav from '@/components/TopNav';
import MyDomains from '@/components/MyDomains';
import SiteFooter from '@/components/SiteFooter';

export default function MyScansPage() {
  return (
    <div className="container">
      <TopNav active="/my-scans" />
      <div className="hero">
        <h1>Your scans</h1>
        <p>Look up domains you&apos;ve previously scanned and jump back into a report.</p>
      </div>
      <MyDomains />
      <SiteFooter />
    </div>
  );
}
