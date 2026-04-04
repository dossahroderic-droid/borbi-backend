import { useEffect, useState } from 'react';
import { getCurrentUser } from '@/lib/api';
import Sidebar from '@/components/Sidebar';

export default function DashboardPage() {
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    setUser(getCurrentUser());
  }, []);

  return (
    <div className="flex">
      <Sidebar />
      <div className="flex-1 ml-64 p-6">
        <h1 className="text-2xl font-bold mb-4">Tableau de bord</h1>
        <p className="text-gray-600">Bienvenue {user?.email || user?.phone} !</p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
          <div className="bg-white p-4 rounded-lg shadow">
            <h3 className="font-semibold">Ventes du jour</h3>
            <p className="text-2xl font-bold text-success">0 FCFA</p>
          </div>
          <div className="bg-white p-4 rounded-lg shadow">
            <h3 className="font-semibold">Clients</h3>
            <p className="text-2xl font-bold text-primary">0</p>
          </div>
          <div className="bg-white p-4 rounded-lg shadow">
            <h3 className="font-semibold">Dettes</h3>
            <p className="text-2xl font-bold text-danger">0 FCFA</p>
          </div>
        </div>
      </div>
    </div>
  );
}
