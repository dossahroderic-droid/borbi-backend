import { useEffect, useState } from 'react';
import Sidebar from '@/components/Sidebar';
import { getClients, createClient, Client } from '@/lib/api';
import toast from 'react-hot-toast';

export default function ClientsPage() {
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    phone: '',
    preferredLanguage: 'fr',
  });

  const loadClients = async () => {
    try {
      const data = await getClients();
      setClients(data);
    } catch (error) {
      toast.error('Erreur chargement des clients');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadClients();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await createClient(formData);
      toast.success('Client ajouté');
      setShowModal(false);
      setFormData({ name: '', phone: '', preferredLanguage: 'fr' });
      loadClients();
    } catch (error) {
      toast.error('Erreur lors de l\'ajout');
    }
  };

  if (loading) {
    return (
      <div className="flex">
        <Sidebar />
        <div className="flex-1 ml-64 p-6">Chargement...</div>
      </div>
    );
  }

  return (
    <div className="flex">
      <Sidebar />
      <div className="flex-1 ml-64 p-6">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-2xl font-bold">Clients</h1>
          <button
            onClick={() => setShowModal(true)}
            className="bg-primary text-white px-4 py-2 rounded-lg"
          >
            + Nouveau client
          </button>
        </div>

        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="p-3 text-left">Nom</th>
                <th className="p-3 text-left">Téléphone</th>
                <th className="p-3 text-left">Dette</th>
                <th className="p-3 text-left">Statut</th>
              </tr>
            </thead>
            <tbody>
              {clients.map((client) => (
                <tr key={client.id} className="border-t">
                  <td className="p-3">{client.name}</td>
                  <td className="p-3">{client.phone}</td>
                  <td className="p-3">
                    <span className={client.debtBalance > 0 ? 'text-danger font-semibold' : 'text-success'}>
                      {client.debtBalance} FCFA
                    </span>
                  </td>
                  <td className="p-3">
                    {client.debtBalance > 0 ? (
                      <span className="text-danger text-sm">⚠️ À régler</span>
                    ) : (
                      <span className="text-success text-sm">✓ À jour</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Modal ajout client */}
        {showModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 w-full max-w-md">
              <h2 className="text-xl font-bold mb-4">Nouveau client</h2>
              <form onSubmit={handleSubmit}>
                <div className="mb-4">
                  <label className="block text-gray-700 mb-2">Nom complet</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="w-full p-2 border rounded"
                    required
                  />
                </div>
                <div className="mb-4">
                  <label className="block text-gray-700 mb-2">Téléphone</label>
                  <input
                    type="tel"
                    value={formData.phone}
                    onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                    className="w-full p-2 border rounded"
                    required
                  />
                </div>
                <div className="mb-4">
                  <label className="block text-gray-700 mb-2">Langue préférée</label>
                  <select
                    value={formData.preferredLanguage}
                    onChange={(e) => setFormData({ ...formData, preferredLanguage: e.target.value })}
                    className="w-full p-2 border rounded"
                  >
                    <option value="fr">Français</option>
                    <option value="wo">Wolof</option>
                    <option value="ar">Arabe</option>
                  </select>
                </div>
                <div className="flex gap-3">
                  <button type="submit" className="flex-1 bg-primary text-white py-2 rounded">
                    Ajouter
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowModal(false)}
                    className="flex-1 bg-gray-300 py-2 rounded"
                  >
                    Annuler
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
