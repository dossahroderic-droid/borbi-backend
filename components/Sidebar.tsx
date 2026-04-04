import Link from 'next/link';
import { useRouter } from 'next/router';
import { logout } from '@/lib/api';

export default function Sidebar() {
  const router = useRouter();

  const handleLogout = () => {
    logout();
    router.push('/login');
  };

  const menuItems = [
    { href: '/dashboard', label: 'Dashboard', icon: '📊' },
    { href: '/stock', label: 'Stock', icon: '📦' },
    { href: '/clients', label: 'Clients', icon: '👥' },
    { href: '/orders', label: 'Commandes', icon: '🛒' },
    { href: '/messages', label: 'Messages', icon: '💬' },
  ];

  return (
    <div className="fixed left-0 top-0 h-screen w-64 bg-gray-900 text-white p-4">
      <h2 className="text-xl font-bold mb-6">Bor‑Bi</h2>
      <nav>
        {menuItems.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className={`flex items-center gap-3 p-3 rounded-lg mb-1 hover:bg-gray-700 ${
              router.pathname === item.href ? 'bg-gray-700' : ''
            }`}
          >
            <span>{item.icon}</span>
            {item.label}
          </Link>
        ))}
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-3 p-3 rounded-lg mt-4 bg-danger hover:bg-red-700"
        >
          <span>🚪</span> Déconnexion
        </button>
      </nav>
    </div>
  );
}
