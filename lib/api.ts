import axios from 'axios';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'https://borbi-api.onrender.com/api';

export const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Ajouter le token JWT automatiquement
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Types
export interface Product {
  id: string;
  nameFr: string;
  nameWolof: string;
  category: string;
  unit: string;
  defaultPrice: number;
  imageUrl?: string;
  brand?: string;
}

export interface VendorProduct {
  id: string;
  productId: string;
  productType: string;
  price: number;
  stock: number;
  productDetails?: Product;
}

export interface Client {
  id: string;
  name: string;
  phone: string;
  debtBalance: number;
}

export interface Transaction {
  id: string;
  clientId: string;
  items: any[];
  totalCents: number;
  paymentStatus: string;
  amountPaid: number;
  remaining: number;
}

// Auth
export const login = async (identifier: string, password: string) => {
  const res = await api.post('/auth/login', { identifier, password });
  if (res.data.token) {
    localStorage.setItem('token', res.data.token);
    localStorage.setItem('user', JSON.stringify(res.data.user));
  }
  return res.data;
};

export const register = async (data: any) => {
  const res = await api.post('/auth/register', data);
  if (res.data.token) {
    localStorage.setItem('token', res.data.token);
    localStorage.setItem('user', JSON.stringify(res.data.user));
  }
  return res.data;
};

export const logout = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  window.location.href = '/login';
};

export const getCurrentUser = () => {
  const user = localStorage.getItem('user');
  return user ? JSON.parse(user) : null;
};

// Produits
export const getDefaultProducts = async (category?: string) => {
  const url = category ? `/products/default?category=${category}` : '/products/default';
  const res = await api.get(url);
  return res.data;
};

export const getCategories = async () => {
  const res = await api.get('/products/categories');
  return res.data.categories;
};

export const getVendorProducts = async () => {
  const res = await api.get('/vendors/products');
  return res.data;
};

export const addVendorProduct = async (data: any) => {
  const res = await api.post('/vendors/products', data);
  return res.data;
};

// Clients
export const getClients = async () => {
  const res = await api.get('/vendors/clients');
  return res.data;
};

export const createClient = async (data: any) => {
  const res = await api.post('/vendors/clients', data);
  return res.data;
};

// Transactions
export const createTransaction = async (data: any) => {
  const res = await api.post('/vendors/transactions', data);
  return res.data;
};

export const getTransactions = async () => {
  const res = await api.get('/vendors/transactions');
  return res.data;
};

// Commandes
export const createOrder = async (data: any) => {
  const res = await api.post('/orders', data);
  return res.data;
};

export const getOrders = async () => {
  const res = await api.get('/orders/vendor');
  return res.data;
};

// Messages
export const getConversations = async () => {
  const res = await api.get('/messages/conversations');
  return res.data;
};

export const getMessages = async (userId: string) => {
  const res = await api.get(`/messages/${userId}`);
  return res.data;
};

export const sendMessage = async (data: any) => {
  const res = await api.post('/messages', data);
  return res.data;
};

// IA
export const chatWithAI = async (question: string, language: string = 'fr') => {
  const res = await api.post('/chat', { question, language });
  return res.data;
};

// Upload image
export const uploadImage = async (file: File) => {
  const formData = new FormData();
  formData.append('file', file);
  const res = await api.post('/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return res.data;
};
