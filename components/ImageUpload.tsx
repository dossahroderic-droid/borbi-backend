import { useState } from 'react';
import { uploadImage } from '@/lib/api';
import Image from 'next/image';

interface ImageUploadProps {
  onUpload: (url: string) => void;
  existingUrl?: string;
}

export default function ImageUpload({ onUpload, existingUrl }: ImageUploadProps) {
  const [uploading, setUploading] = useState(false);
  const [preview, setPreview] = useState(existingUrl || '');

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    try {
      const data = await uploadImage(file);
      setPreview(data.url);
      onUpload(data.url);
    } catch (error) {
      console.error('Upload failed', error);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="border rounded-lg p-4 text-center">
      {preview ? (
        <div className="relative h-40 w-full mb-3">
          <Image src={preview} alt="Preview" fill className="object-cover rounded" />
          <button
            onClick={() => setPreview('')}
            className="absolute top-1 right-1 bg-red-500 text-white rounded-full w-6 h-6"
          >
            ×
          </button>
        </div>
      ) : (
        <div className="h-40 bg-gray-100 flex items-center justify-center text-gray-400 mb-3">
          📷 Aucune image
        </div>
      )}
      <label className="cursor-pointer bg-primary text-white px-4 py-2 rounded-lg inline-block">
        {uploading ? 'Upload...' : 'Choisir une image'}
        <input type="file" accept="image/*" onChange={handleFileChange} className="hidden" disabled={uploading} />
      </label>
    </div>
  );
}
