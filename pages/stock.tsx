import { useEffect, useState } from 'react';
import Sidebar from '@/components/Sidebar';
import { getVendorProducts, addVendorProduct, getDefaultProducts, Product } from '@/lib/api';
import toast from 'react-hot-toast';
import Image from 'next/image';

export default function StockPage() {
  const [products, setProducts] = useState<any[]>([]);
  const [defaultProducts, setDefaultProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [selectedProduct, setSelectedProduct] = useState<Product | null>(null);
  const [price, setPrice] = useState('');
  const [stock, setStock] = useState('');

  const loadProducts = async () => {
    try {
      const [vendorProducts, defaultProds] = await Promise.all([
        getVendorProducts(),
        getDefaultProducts(),
      ]);
      setProducts(vendorProducts);
      setDefaultProducts(defaultProds);
    } catch (error) {
      toast.error('Erreur chargement des produits');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadProducts();
  }, []);

  const handleAddProduct = async () => {
    if (!selectedProduct || !price || !stock) {
      toast.error('Veuillez remplir tous les champs');
      return;
    }

    try {
      await addVendorProduct({
        productId: selectedProduct.id,
        productType: 'DefaultProduct',
        price: parseInt(price),
        stock: parseInt(stock),
      });
      toast.success('Produit ajouté au catalogue');
      setShowModal(false);
      setSelectedProduct(null);
      setPrice('');
      setStock('');
      loadProducts();
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
          <h1 className="text-2xl font-bold">Gestion du stock</h1>
          <button
            onClick={() => setShowModal(true)}
            className="bg-primary text-white px-4 py-2 rounded-lg"
          >
            + Ajouter un produit
          </button>
        </div>

        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="p-3 text-left">Produit</th>
                <th className="p-3 text-left">Prix</th>
                <th className="p-3 text-left">Stock</th>
                <th className="p-3 text-left">Statut</th>
              </tr>
            </thead>
            <tbody>
              {products.map((product) => (
                <tr key={product.id} className="border-t">
                  <td className="p-3">
                    <div className="flex items-center gap-3">
                      {product.productDetails?.imageUrl && (
                        <div className="relative h-10 w-10">
                          <Image
                            src={product.productDetails.imageUrl}
                            alt={product.productDetails.nameFr}
                            fill
                            className="object-cover rounded"
                          />
                        </div>
                      )}
                      <span>{product.productDetails?.nameFr || product.productId}</span>
                    </div>
                  </td>
                  <td className="p-3">{product.price} FCFA</td>
                  <td className="p-3">
                    <span className={product.stock < 5 ? 'text-danger font-semibold' : ''}>
                      {product.stock}
                    </span>
                  </td>
                  <td className="p-3">
                    {product.stock < 5 ? (
                      <span className="text-danger text-sm">⚠️ Stock bas</span>
                    ) : (
                      <span className="text-success text-sm">✓ Disponible</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Modal ajout produit */}
        {showModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 w-full max-w-md">
              <h2 className="text-xl font-bold mb-4">Ajouter un produit</h2>
              <div className="mb-4">
                <label className="block text-gray-700 mb-2">Produit</label>
                <select
                  className="w-full p-2 border rounded"
                  value={selectedProduct?.id || ''}
                  onChange={(e) => {
                    const product = defaultProducts.find(p => p.id === e.target.value);
                    setSelectedProduct(product || null);
                  }}
                >
                  <option value="">Sélectionner un produit</option>
                  {defaultProducts.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.nameFr} - {p.defaultPrice} FCFA
                    </option>
                  ))}
                </select>
              </div>
              <div className="mb-4">
                <label className="block text-gray-700 mb-2">Prix de vente (FCFA)</label>
                <input
                  type="number"
                  value={price}
                  onChange={(e) => setPrice(e.target.value)}
                  className="w-full p-2 border rounded"
                  placeholder="Ex: 1500"
                />
              </div>
              <div className="mb-4">
                <label className="block text-gray-700 mb-2">Quantité en stock</label>
                <input
                  type="number"
                  value={stock}
                  onChange={(e) => setStock(e.target.value)}
                  className="w-full p-2 border rounded"
                  placeholder="Ex: 10"
                />
              </div>
              <div className="flex gap-3">
                <button
                  onClick={handleAddProduct}
                  className="flex-1 bg-primary text-white py-2 rounded"
                >
                  Ajouter
                </button>
                <button
                  onClick={() => {
                    setShowModal(false);
                    setSelectedProduct(null);
                    setPrice('');
                    setStock('');
                  }}
                  className="flex-1 bg-gray-300 py-2 rounded"
                >
                  Annuler
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
