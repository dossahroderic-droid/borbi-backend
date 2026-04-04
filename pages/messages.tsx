import { useEffect, useState } from 'react';
import Sidebar from '@/components/Sidebar';
import { getConversations, getMessages, sendMessage } from '@/lib/api';
import toast from 'react-hot-toast';

export default function MessagesPage() {
  const [conversations, setConversations] = useState<any[]>([]);
  const [selectedUser, setSelectedUser] = useState<any>(null);
  const [messages, setMessages] = useState<any[]>([]);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(true);

  const loadConversations = async () => {
    try {
      const data = await getConversations();
      setConversations(data);
    } catch (error) {
      toast.error('Erreur chargement des conversations');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadConversations();
  }, []);

  const loadMessages = async (userId: string) => {
    try {
      const data = await getMessages(userId);
      setMessages(data);
    } catch (error) {
      toast.error('Erreur chargement des messages');
    }
  };

  const handleSend = async () => {
    if (!newMessage.trim() || !selectedUser) return;

    try {
      await sendMessage({
        receiverId: selectedUser.participantId,
        receiverType: selectedUser.participantType,
        content: newMessage,
      });
      setNewMessage('');
      loadMessages(selectedUser.participantId);
    } catch (error) {
      toast.error('Erreur lors de l\'envoi');
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
        <h1 className="text-2xl font-bold mb-6">Messages</h1>

        <div className="flex gap-6 h-[calc(100vh-120px)]">
          {/* Liste des conversations */}
          <div className="w-80 bg-white rounded-lg shadow overflow-hidden">
            <div className="p-3 bg-gray-50 border-b font-semibold">Conversations</div>
            <div className="overflow-y-auto h-full">
              {conversations.length === 0 ? (
                <div className="p-4 text-center text-gray-500">Aucune conversation</div>
              ) : (
                conversations.map((conv) => (
                  <div
                    key={conv.participantId}
                    onClick={() => {
                      setSelectedUser(conv);
                      loadMessages(conv.participantId);
                    }}
                    className={`p-3 border-b cursor-pointer hover:bg-gray-50 ${
                      selectedUser?.participantId === conv.participantId ? 'bg-blue-50' : ''
                    }`}
                  >
                    <div className="font-semibold">
                      {conv.participantType === 'vendor' ? 'Vendeur' : 'Grossiste'}
                    </div>
                    <div className="text-sm text-gray-600 truncate">
                      {conv.lastMessage?.content}
                    </div>
                    {conv.unreadCount > 0 && (
                      <span className="inline-block mt-1 bg-primary text-white text-xs px-2 py-0.5 rounded-full">
                        {conv.unreadCount}
                      </span>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Zone de chat */}
          <div className="flex-1 bg-white rounded-lg shadow flex flex-col">
            {selectedUser ? (
              <>
                <div className="p-3 bg-gray-50 border-b font-semibold">
                  Conversation avec {selectedUser.participantType === 'vendor' ? 'Vendeur' : 'Grossiste'}
                </div>
                <div className="flex-1 overflow-y-auto p-4 space-y-3">
                  {messages.map((msg) => (
                    <div
                      key={msg.id}
                      className={`flex ${msg.senderType === 'vendor' ? 'justify-start' : 'justify-end'}`}
                    >
                      <div
                        className={`max-w-[70%] p-3 rounded-lg ${
                          msg.senderType === 'vendor'
                            ? 'bg-gray-100 text-gray-800'
                            : 'bg-primary text-white'
                        }`}
                      >
                        {msg.content}
                        <div className="text-xs opacity-70 mt-1">
                          {new Date(msg.createdAt).toLocaleTimeString()}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="p-3 border-t flex gap-2">
                  <input
                    type="text"
                    value={newMessage}
                    onChange={(e) => setNewMessage(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleSend()}
                    placeholder="Écrivez votre message..."
                    className="flex-1 p-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                  />
                  <button
                    onClick={handleSend}
                    className="bg-primary text-white px-4 py-2 rounded-lg"
                  >
                    Envoyer
                  </button>
                </div>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center text-gray-500">
                Sélectionnez une conversation
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
