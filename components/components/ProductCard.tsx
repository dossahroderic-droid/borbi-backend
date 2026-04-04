import Image from 'next/image';

interface ProductCardProps {
  id: string;
  name: string;
  price: number;
  unit: string;
  imageUrl?: string;
  brand?: string;
  onSelect?: () => void;
}

export default function ProductCard({ name, price, unit, imageUrl, brand, onSelect }: ProductCardProps) {
  return (
    <div
      onClick={onSelect}
      className="border rounded-lg p-3 shadow-sm hover:shadow-md cursor-pointer transition"
    >
      <div className="relative h-32 w-full bg-gray-100 rounded mb-2">
        {imageUrl ? (
          <Image src={imageUrl} alt={name} fill className="object-cover rounded" />
        ) : (
          <div className="flex items-center justify-center h-full text-gray-400">📷</div>
        )}
      </div>
      <h3 className="font-semibold text-sm">{name}</h3>
      <p className="text-success font-bold text-sm">{price} FCFA / {unit}</p>
      {brand && <p className="text-xs text-gray-500">{brand}</p>}
    </div>
  );
}
