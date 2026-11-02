import React, { useState, useEffect } from 'react';
import { Sidebar, NavItem } from './components/Sidebar';
import { Header } from './components/Header';
import { DashboardView } from './components/DashboardView';
import { ProductsView } from './components/ProductsView';
import { DiscountsView } from './components/DiscountsView';
import { ProductCategoriesView } from './components/ProductCategoriesView';
import { PostsView } from './components/PostsView';
import { PostCategoriesView } from './components/PostCategoriesView';
import { ContactMessagesView } from './components/ContactMessagesView';
import { OrdersView } from './components/OrdersView';
import { BotSettingsView } from './components/BotSettingsView';
import { AccountView } from './components/AccountView';
import { StorefrontView } from './components/StorefrontView';
import { PageEditorView } from './components/PageEditorView';
import { PaymentSettingsView } from './components/PaymentSettingsView';
import { ConsultationsAdminView } from './components/ConsultationsAdminView';
import { SeoManagementView } from './components/SeoManagementView';
import { SearchEnginesView } from './components/SearchEnginesView';
import { ErrorBoundary } from './components/ErrorBoundary';
import {
  apiFetch,
  hasAdminSession,
  setAdminSessionToken,
  clearAdminSessionToken,
  getCachedLocalState,
  getServerConnectionStatus,
  subscribeServerConnectionStatus,
  subscribeAuthEvents,
} from './services/dataService';
import {
  AuthState,
  viewAfterLogin,
  shouldFetchAdminData,
  handleSetupSuccess,
} from './authFlow';
import { DEFAULT_ADMIN_CREDENTIALS } from './services/seedData';
import { 
  Product, 
  ProductCategory, 
  Post, 
  PostCategory, 
  ContactMessage, 
  Order, 
  TelegramConfig, 
  BotActivityLog,
  AdminStats,
  SiteContent
} from './types';

export default function App() {
  const initialLocalData = getCachedLocalState();

  const [viewMode, setViewMode] = useState<'admin' | 'storefront'>(() => {
    if (typeof window !== 'undefined' && window.location.pathname.startsWith('/admin')) {
      return 'admin';
    }
    return 'storefront';
  });
  const [authState, setAuthState] = useState<AuthState>('unknown');
  const [isAdminAuthenticated, setIsAdminAuthenticated] = useState<boolean>(false);
  const [adminLoginUser, setAdminLoginUser] = useState('');
  const [adminLoginPass, setAdminLoginPass] = useState('');
  const [adminLoginError, setAdminLoginError] = useState('');
  const [adminLoginSuccess, setAdminLoginSuccess] = useState('');
  const [isLoggingInAdmin, setIsLoggingInAdmin] = useState(false);
  const [initialSetupCompleted, setInitialSetupCompleted] = useState<boolean | null>(null);

  const [activeTab, setActiveTab] = useState<NavItem>('dashboard');
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'offline_fallback'>(() =>
    getServerConnectionStatus()
  );

  // States initialized immediately with cached/seed data to prevent blank screen or empty shell
  const [stats, setStats] = useState<AdminStats>(() => ({
    totalProducts: initialLocalData.products.filter((p) => !p.isDelete).length,
    totalPosts: initialLocalData.posts.filter((p) => !p.isDelete).length,
    unreadMessages: initialLocalData.contactMessages.filter((m) => !m.isRead).length,
    pendingOrders: initialLocalData.orders.length,
    totalRevenue: initialLocalData.orders.reduce((acc, o) => acc + (Number(o.totalPrice) || 0), 0),
  }));

  const [products, setProducts] = useState<Product[]>(() => initialLocalData.products);
  const [productCategories, setProductCategories] = useState<ProductCategory[]>(
    () => initialLocalData.productCategories
  );
  const [posts, setPosts] = useState<Post[]>(() => initialLocalData.posts);
  const [postCategories, setPostCategories] = useState<PostCategory[]>(
    () => initialLocalData.postCategories
  );
  const [messages, setMessages] = useState<ContactMessage[]>(() => initialLocalData.contactMessages);
  const [orders, setOrders] = useState<Order[]>(() => initialLocalData.orders);
  const [siteContent, setSiteContent] = useState<SiteContent>(() => initialLocalData.siteContent);
  const [botLogs, setBotLogs] = useState<BotActivityLog[]>(() => initialLocalData.botActivityLogs);
  const [botConfig, setBotConfig] = useState<TelegramConfig>(() => initialLocalData.telegramConfig);

  // Load public storefront data + protected admin data (with automatic local fallback)
  const fetchData = async (forceAdminFetch = false) => {
    try {
      const [prodRes, prodCatRes, postRes, postCatRes, contentRes] = await Promise.all([
        apiFetch('/api/products').then((r) => (r.ok ? r.json() : null)).catch(() => null),
        apiFetch('/api/product-categories').then((r) => (r.ok ? r.json() : null)).catch(() => null),
        apiFetch('/api/posts').then((r) => (r.ok ? r.json() : null)).catch(() => null),
        apiFetch('/api/post-categories').then((r) => (r.ok ? r.json() : null)).catch(() => null),
        apiFetch('/api/site-content').then((r) => (r.ok ? r.json() : null)).catch(() => null),
      ]);

      if (Array.isArray(prodRes) && prodRes.length > 0) {
        setProducts(prodRes);
      }
      if (Array.isArray(prodCatRes) && prodCatRes.length > 0) {
        setProductCategories(prodCatRes);
      }
      if (Array.isArray(postRes) && postRes.length > 0) {
        setPosts(postRes);
      }
      if (Array.isArray(postCatRes) && postCatRes.length > 0) {
        setPostCategories(postCatRes);
      }
      if (contentRes) {
        setSiteContent(contentRes);
      }

      const canFetchAdmin = shouldFetchAdminData(
        initialSetupCompleted === false,
        forceAdminFetch || (hasAdminSession() && authState === 'authenticated'),
        authState
      );
      if (canFetchAdmin) {
        const [statsRes, msgRes, ordersRes, botRes] = await Promise.all([
          apiFetch('/api/stats').then((r) => (r.ok ? r.json() : null)).catch(() => null),
          apiFetch('/api/contact').then((r) => (r.ok ? r.json() : null)).catch(() => null),
          apiFetch('/api/orders').then((r) => (r.ok ? r.json() : null)).catch(() => null),
          apiFetch('/api/bot/config').then((r) => (r.ok ? r.json() : null)).catch(() => null),
        ]);

        if (statsRes && !statsRes.error) setStats(statsRes);
        if (Array.isArray(msgRes)) setMessages(msgRes);
        if (Array.isArray(ordersRes)) setOrders(ordersRes);
        if (botRes?.config) setBotConfig(botRes.config);
        if (Array.isArray(botRes?.logs)) setBotLogs(botRes.logs);
      }
    } catch (err) {
      console.warn('Data sync check completed with local cache preserved:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    const unsubStatus = subscribeServerConnectionStatus((status) => {
      setConnectionStatus(status);
    });

    const unsubAuth = subscribeAuthEvents((event) => {
      if (event === 'SETUP_REQUIRED') {
        setInitialSetupCompleted(false);
        setAuthState('pending');
        setActiveTab('account');
      } else if (event === 'UNAUTHORIZED') {
        clearAdminSessionToken();
        setIsAdminAuthenticated(false);
        setAuthState('unauthenticated');
        setInitialSetupCompleted(null);
        setActiveTab('dashboard');
      }
    });

    const initAuth = async () => {
      if (!hasAdminSession()) {
        setAuthState('unauthenticated');
        setIsAdminAuthenticated(false);
        setInitialSetupCompleted(null);
        await fetchData();
        return;
      }

      try {
        const res = await apiFetch('/api/admin/verify-session');
        if (res.ok) {
          const data = await res.json().catch(() => null);
          const isDone = Boolean(data?.profile?.initialSetupCompleted);
          setIsAdminAuthenticated(true);
          setInitialSetupCompleted(isDone);
          if (!isDone) {
            setAuthState('pending');
            setActiveTab('account');
            await fetchData();
          } else {
            setAuthState('authenticated');
            await fetchData(true);
          }
        } else {
          clearAdminSessionToken();
          setIsAdminAuthenticated(false);
          setAuthState('unauthenticated');
          setInitialSetupCompleted(null);
          await fetchData();
        }
      } catch {
        clearAdminSessionToken();
        setIsAdminAuthenticated(false);
        setAuthState('unauthenticated');
        setInitialSetupCompleted(null);
        await fetchData();
      }
    };

    initAuth();

    return () => {
      unsubStatus();
      unsubAuth();
    };
  }, []);

  // Handlers for Products
  const handleAddProduct = async (prod: Partial<Product>) => {
    const res = await apiFetch('/api/products', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(prod),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'خطا در ثبت محصول');
    }
    await fetchData();
  };

  const handleEditProduct = async (id: number, prod: Partial<Product>) => {
    const res = await apiFetch(`/api/products/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(prod),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'خطا در ویرایش محصول');
    }
    await fetchData();
  };

  const handleDeleteProduct = async (id: number) => {
    const res = await apiFetch(`/api/products/${id}`, { method: 'DELETE' });
    if (res.ok) {
      await fetchData();
    }
  };

  // Handlers for Product Categories
  const handleAddProductCategory = async (cat: Partial<ProductCategory>) => {
    const res = await apiFetch('/api/product-categories', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cat),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'خطا در ثبت دسته‌بندی');
    }
    await fetchData();
  };

  const handleEditProductCategory = async (id: number, cat: Partial<ProductCategory>) => {
    const res = await apiFetch(`/api/product-categories/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cat),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'خطا در ویرایش دسته‌بندی');
    }
    await fetchData();
  };

  const handleDeleteProductCategory = async (id: number) => {
    const res = await apiFetch(`/api/product-categories/${id}`, { method: 'DELETE' });
    if (res.ok) {
      await fetchData();
    }
  };

  // Handlers for Posts
  const handleAddPost = async (post: Partial<Post>) => {
    const res = await apiFetch('/api/posts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(post),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'خطا در ثبت مقاله');
    }
    await fetchData();
  };

  const handleEditPost = async (id: number, post: Partial<Post>) => {
    const res = await apiFetch(`/api/posts/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(post),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'خطا در ویرایش مقاله');
    }
    await fetchData();
  };

  const handleDeletePost = async (id: number) => {
    const res = await apiFetch(`/api/posts/${id}`, { method: 'DELETE' });
    if (res.ok) {
      await fetchData();
    }
  };

  // Handlers for Post Categories
  const handleAddPostCategory = async (cat: { title: string; parentId?: number | null }) => {
    const res = await apiFetch('/api/post-categories', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cat),
    });
    if (res.ok) {
      await fetchData();
    }
  };

  const handleDeletePostCategory = async (id: number) => {
    const res = await apiFetch(`/api/post-categories/${id}`, { method: 'DELETE' });
    if (res.ok) {
      await fetchData();
    }
  };

  // Handlers for Messages
  const handleRespondMessage = async (id: number, response: string) => {
    const res = await apiFetch(`/api/contact/${id}/respond`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ response }),
    });
    if (res.ok) {
      await fetchData();
    }
  };

  const handleDeleteMessage = async (id: number) => {
    const res = await apiFetch(`/api/contact/${id}`, { method: 'DELETE' });
    if (res.ok) {
      await fetchData();
    }
  };

  const handleMarkMessageRead = async (id: number) => {
    setMessages(prev => prev.map(m => (m.id === id ? { ...m, isRead: true } : m)));
  };

  // Handlers for Orders
  const handleUpdateOrderStatus = async (
    id: number,
    status: Order['status'],
    paymentStatus?: Order['paymentStatus']
  ) => {
    const res = await apiFetch(`/api/orders/${id}/status`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, paymentStatus }),
    });
    if (res.ok) {
      await fetchData();
    }
  };

  const handleVerifyReceipt = async (id: number, approved: boolean) => {
    const res = await apiFetch(`/api/orders/${id}/verify-receipt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approved }),
    });
    if (res.ok) {
      await fetchData();
    }
  };

  // Handlers for Bot
  const handleUpdateBotConfig = async (newConfig: Partial<TelegramConfig>) => {
    const res = await apiFetch('/api/bot/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newConfig),
    });
    if (res.ok) {
      const data = await res.json();
      if (data.config) setBotConfig(data.config);
      await fetchData();
    }
  };

  const handleSimulateBotEvent = async (type: string, payload?: any) => {
    const res = await apiFetch('/api/bot/simulate-event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, payload }),
    });
    const data = await res.json();
    await fetchData();
    return data;
  };

  // Handlers for Credentials
  const handleUpdateCredentials = async (email: string, newPass: string, currentPassword?: string, username?: string) => {
    const res = await apiFetch('/api/account/change-credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, newPassword: newPass, currentPassword, username }),
    });
    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.error || 'خطا در ثبت مشخصات');
    }
  };

  // Handlers for Storefront Actions
  const handlePlaceOrder = async (orderData: Partial<Order>) => {
    try {
      const res = await apiFetch('/api/orders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(orderData),
      });
      if (res.ok) {
        const data = await res.json().catch(() => null);
        await fetchData();
        return data?.order || data;
      }
    } catch (err) {
      console.warn('handlePlaceOrder fallback caught:', err);
    }
    return null;
  };

  const handleSubmitContact = async (contactData: { fullName: string; phoneNumber?: string; message: string }) => {
    const res = await apiFetch('/api/contact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(contactData),
    });
    if (res.ok) {
      const data = await res.json();
      await fetchData();
      return data;
    }
  };

  // Handlers for Site Content Management
  const handleSaveSiteContent = async (newContent: SiteContent): Promise<void> => {
    const res = await apiFetch('/api/site-content', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newContent),
    });
    if (res.ok) {
      const data = await res.json();
      if (data.siteContent) {
        setSiteContent(data.siteContent);
      }
    } else {
      const err = await res.json();
      throw new Error(err.error || 'خطا در ذخیره محتوای سایت');
    }
  };

  const handleResetSiteContent = async () => {
    const res = await apiFetch('/api/site-content/reset', { method: 'POST' });
    if (res.ok) {
      const data = await res.json();
      if (data.siteContent) {
        setSiteContent(data.siteContent);
      }
    }
  };

  const getSectionTitle = (tab: NavItem) => {
    switch (tab) {
      case 'dashboard':
        return 'داشبورد عمومی';
      case 'products':
        return 'مدیریت محصولات';
      case 'discounts':
        return 'مدیریت تخفیف‌ها و پیشنهاد شگفت‌انگیز';
      case 'product-categories':
        return 'دسته‌بندی محصولات';
      case 'posts':
        return 'مقالات و اخبار وبلاگ';
      case 'post-categories':
        return 'دسته‌بندی مقالات';
      case 'consultations':
        return 'مدیریت رزروها، قیمت، موضوعات و شبکه‌های اجتماعی مشاوره';
      case 'messages':
        return 'پیام‌ها و پشتیبانی کاربران';
      case 'orders':
        return 'مدیریت سفارشات و تایید فیش‌های واریزی';
      case 'payment-settings':
        return 'تنظیمات صفحه پرداخت، شماره کارت و درگاه بانکی';
      case 'page-editor':
        return 'اصلاح صفحات، عناوین و چیدمان محتوا';
      case 'seo':
        return 'سئو تکنیکال، نقشه سایت، ریدایرکت ۳۰۱ و داده ساختاریافته (JSON-LD)';
      case 'search-engines':
        return 'اتصال به موتورهای جستجو و اینماد (ترب، ایمالز، اینماد)';
      case 'bot':
        return 'مرکز فرماندهی ربات‌های بله و تلگرام و درگاه‌های ارتباطی پشتیبانی';
      case 'account':
        return 'امنیت و تنظیمات مدیر';
    }
  };

  const switchToStorefront = () => {
    if (typeof window !== 'undefined' && window.location.pathname.startsWith('/admin')) {
      window.history.pushState({}, '', '/');
    }
    setViewMode('storefront');
  };

  const handleLogout = async () => {
    try {
      await apiFetch('/api/admin/logout', { method: 'POST' });
    } catch {}
    clearAdminSessionToken();
    setIsAdminAuthenticated(false);
    setAuthState('unauthenticated');
    setInitialSetupCompleted(null);
    setActiveTab('dashboard');
    switchToStorefront();
  };

  const handleSetupCompletedFlow = () => {
    const successRes = handleSetupSuccess();
    clearAdminSessionToken();
    setIsAdminAuthenticated(false);
    setAuthState('unauthenticated');
    setInitialSetupCompleted(true);
    setActiveTab(successRes.targetTab);
    setAdminLoginError('');
    setAdminLoginSuccess(successRes.successMessage);
  };

  const handleDirectAdminLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAdminLoginError('');
    const u = adminLoginUser.trim();
    const p = adminLoginPass.trim();
    if (!u || !p) {
      setAdminLoginError('لطفاً نام کاربری و رمز عبور مدیریت را وارد نمایید.');
      return;
    }
    setIsLoggingInAdmin(true);
    try {
      const res = await apiFetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.ok) {
        if (data.token) {
          setAdminSessionToken(data.token);
        }
        setIsAdminAuthenticated(true);
        const targetTab = viewAfterLogin(data);
        const isPending = targetTab === 'account';
        setInitialSetupCompleted(!isPending);
        setAuthState(isPending ? 'pending' : 'authenticated');
        setActiveTab(targetTab);
        setAdminLoginUser('');
        setAdminLoginPass('');
        setAdminLoginError('');
        setAdminLoginSuccess('');
        if (!isPending) {
          await fetchData(true);
        }
      } else {
        setAdminLoginError(data.error || 'نام کاربری یا رمز عبور مدیریت اشتباه است.');
      }
    } catch {
      setAdminLoginError('خطا در برقراری ارتباط با سرور. لطفاً مجدداً تلاش نمایید.');
    } finally {
      setIsLoggingInAdmin(false);
    }
  };

  if (viewMode === 'storefront') {
    return (
      <ErrorBoundary
        fallbackTitle="خطا در نمایش فروشگاه یا فرایند پرداخت"
        onReset={() => {
          if (typeof window !== 'undefined') {
            window.history.pushState({}, '', '/');
          }
          fetchData();
        }}
      >
        <StorefrontView
          products={products}
          categories={productCategories}
          posts={posts}
          messages={messages}
          botConfig={botConfig}
          siteContent={siteContent || undefined}
          onBackToAdmin={() => {
            if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/admin')) {
              window.history.pushState({}, '', '/admin');
            }
            setIsAdminAuthenticated(hasAdminSession());
            fetchData(true);
            setViewMode('admin');
          }}
          onPlaceOrder={handlePlaceOrder}
          onSubmitContact={handleSubmitContact}
          onOrderUpdated={() => fetchData()}
        />
      </ErrorBoundary>
    );
  }

  if (authState === 'unknown') {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4" dir="rtl">
        <div className="text-white text-xs font-bold flex items-center gap-2">
          <span className="w-4 h-4 border-2 border-amber-500 border-t-transparent rounded-full animate-spin"></span>
          <span>در حال بررسی نشست مدیریت...</span>
        </div>
      </div>
    );
  }

  if (!isAdminAuthenticated) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4" dir="rtl">
        <div className="bg-white rounded-3xl max-w-md w-full p-7 shadow-2xl border border-slate-100 text-center">
          <div className="w-14 h-14 rounded-2xl bg-amber-500 text-white flex items-center justify-center mx-auto mb-4 font-black text-xl shadow-lg shadow-amber-500/25">
            ONV
          </div>
          <h1 className="text-lg font-black text-slate-900">
            احراز هویت پنل مدیریت ({siteContent?.brandName || 'اونیوال'})
          </h1>
          <p className="text-xs text-slate-500 mt-1 mb-4">
            دسترسی به مسیر <code dir="ltr">/admin</code> نیازمند ورود با حساب رسمی مدیریت است.
          </p>

          <form onSubmit={handleDirectAdminLogin} className="space-y-4 text-right">
            <div>
              <label className="block text-xs font-bold text-slate-700 mb-1.5">
                نام کاربری یا ایمیل مدیریت
              </label>
              <input
                type="text"
                required
                dir="ltr"
                value={adminLoginUser}
                onChange={(e) => setAdminLoginUser(e.target.value)}
                placeholder="نام کاربری یا ایمیل مدیریت"
                className="w-full px-4 py-2.5 rounded-xl border border-slate-200 text-xs font-mono text-center focus:outline-none focus:ring-2 focus:ring-amber-500/20"
              />
            </div>

            <div>
              <label className="block text-xs font-bold text-slate-700 mb-1.5">
                رمز عبور مدیریت
              </label>
              <input
                type="password"
                required
                dir="ltr"
                value={adminLoginPass}
                onChange={(e) => setAdminLoginPass(e.target.value)}
                placeholder="••••••••"
                className="w-full px-4 py-2.5 rounded-xl border border-slate-200 text-xs font-mono text-center focus:outline-none focus:ring-2 focus:ring-amber-500/20"
              />
            </div>

            {adminLoginSuccess && (
              <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-bold text-center leading-relaxed">
                {adminLoginSuccess}
              </div>
            )}

            {adminLoginError && (
              <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs font-bold text-center">
                {adminLoginError}
              </div>
            )}

            <div className="flex gap-2.5 pt-2">
              <button
                type="button"
                onClick={switchToStorefront}
                className="flex-1 py-2.5 border border-slate-200 text-slate-600 rounded-xl text-xs font-bold hover:bg-slate-50 cursor-pointer"
              >
                بازگشت به فروشگاه
              </button>
              <button
                type="submit"
                disabled={isLoggingInAdmin}
                className="flex-1 py-2.5 bg-amber-500 hover:bg-amber-600 text-white rounded-xl text-xs font-bold shadow-md cursor-pointer disabled:opacity-50"
              >
                {isLoggingInAdmin ? 'در حال بررسی...' : 'ورود به پنل مدیریت'}
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  }

  return (
    <ErrorBoundary
      fallbackTitle="بروز خطا در بخش مدیریت"
      onReset={() => {
        setActiveTab('dashboard');
        fetchData();
      }}
    >
      <div className="flex h-screen bg-slate-50 overflow-hidden" dir="rtl">
        {/* Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        unreadMessagesCount={stats.unreadMessages}
        pendingOrdersCount={stats.pendingOrders}
        isOpen={isSidebarOpen}
        onClose={() => setIsSidebarOpen(false)}
        onViewStorefront={switchToStorefront}
        onLogout={handleLogout}
        brandName={siteContent?.brandName}
        brandEnglishName={siteContent?.brandEnglishName}
        siteLogo={siteContent?.siteLogo}
        siteLogoFit={siteContent?.siteLogoFit}
        siteLogoShape={siteContent?.siteLogoShape}
        siteLogoScale={siteContent?.siteLogoScale}
        initialSetupCompleted={initialSetupCompleted}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header
          onMenuClick={() => setIsSidebarOpen(!isSidebarOpen)}
          title={getSectionTitle(activeTab)}
          unreadMessagesCount={stats.unreadMessages}
          pendingOrdersCount={stats.pendingOrders}
          searchQuery={searchQuery}
          setSearchQuery={setSearchQuery}
          onViewStorefront={switchToStorefront}
          onNavigate={(tab) => setActiveTab(tab)}
          orders={orders}
          messages={messages}
          onMarkMessageRead={handleMarkMessageRead}
          siteLogo={siteContent?.siteLogo}
        />

        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8">
          <div className="max-w-7xl mx-auto">
            {isLoading ? (
              <div className="flex flex-col items-center justify-center py-24 text-slate-400">
                <div className="w-10 h-10 border-4 border-blue-500/20 border-t-blue-600 rounded-full animate-spin mb-3"></div>
                <div className="text-xs font-medium">در حال فراخوانی داده‌های انیوال...</div>
              </div>
            ) : !initialSetupCompleted ? (
              <div className="space-y-6">
                <div className="p-4 rounded-2xl bg-gradient-to-r from-amber-500 via-amber-600 to-orange-500 text-white shadow-lg flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-white/20 backdrop-blur-xs flex items-center justify-center text-xl shrink-0">🛡️</div>
                  <div>
                    <h4 className="font-black text-sm">راه‌اندازی اولیه: تعیین نام کاربری و رمز عبور دائمی جدید</h4>
                    <p className="text-xs text-white/90 mt-0.5 leading-relaxed">
                      دسترسی به سایر بخش‌های پنل مدیریت تا زمان تکمیل راه‌اندازی اولیه مسدود است. لطفاً مشخصات دائمی جدید خود را ثبت فرمایید.
                    </p>
                  </div>
                </div>
                <AccountView
                  siteContent={siteContent || undefined}
                  onUpdateSiteContent={async (c) => {
                    await handleSaveSiteContent(c);
                    return true;
                  }}
                  onRefreshData={fetchData}
                  initialSetupCompleted={false}
                  onSetupCompleted={handleSetupCompletedFlow}
                />
              </div>
            ) : (
              <>

                {activeTab === 'dashboard' && (
                  <DashboardView
                    stats={stats}
                    products={products}
                    posts={posts}
                    messages={messages}
                    orders={orders}
                    botConfig={botConfig}
                    onNavigate={setActiveTab}
                    onOpenAddProduct={() => setActiveTab('products')}
                    onOpenAddPost={() => setActiveTab('posts')}
                    onTestBot={() => handleSimulateBotEvent('test_notification')}
                    onViewStorefront={switchToStorefront}
                  />
                )}

                {activeTab === 'products' && (
                  <ProductsView
                    products={products}
                    categories={productCategories}
                    onAddProduct={handleAddProduct}
                    onEditProduct={handleEditProduct}
                    onDeleteProduct={handleDeleteProduct}
                  />
                )}

                {activeTab === 'discounts' && (
                  <DiscountsView
                    products={products}
                    categories={productCategories}
                    onEditProduct={handleEditProduct}
                    onViewStorefront={switchToStorefront}
                  />
                )}

                {activeTab === 'product-categories' && (
                  <ProductCategoriesView
                    categories={productCategories}
                    onAddCategory={handleAddProductCategory}
                    onEditCategory={handleEditProductCategory}
                    onDeleteCategory={handleDeleteProductCategory}
                  />
                )}

                {activeTab === 'posts' && (
                  <PostsView
                    posts={posts}
                    categories={postCategories}
                    onAddPost={handleAddPost}
                    onEditPost={handleEditPost}
                    onDeletePost={handleDeletePost}
                  />
                )}

                {activeTab === 'post-categories' && (
                  <PostCategoriesView
                    categories={postCategories}
                    onAddCategory={handleAddPostCategory}
                    onDeleteCategory={handleDeletePostCategory}
                  />
                )}

                {activeTab === 'consultations' && siteContent && (
                  <ConsultationsAdminView
                    siteContent={siteContent}
                    orders={orders}
                    messages={messages}
                    onSaveSiteContent={handleSaveSiteContent}
                    onRespondMessage={handleRespondMessage}
                    onUpdateOrderStatus={handleUpdateOrderStatus}
                    onVerifyReceipt={handleVerifyReceipt}
                    onOpenPaymentSettings={() => setActiveTab('payment-settings')}
                    onViewStorefront={switchToStorefront}
                  />
                )}

                {activeTab === 'messages' && (
                  <ContactMessagesView
                    messages={messages}
                    onRespond={handleRespondMessage}
                    onDelete={handleDeleteMessage}
                  />
                )}

                {activeTab === 'orders' && (
                  <OrdersView
                    orders={orders}
                    onUpdateOrderStatus={handleUpdateOrderStatus}
                    onVerifyReceipt={handleVerifyReceipt}
                    onOpenPaymentSettings={() => setActiveTab('payment-settings')}
                  />
                )}

                {activeTab === 'payment-settings' && siteContent && (
                  <PaymentSettingsView
                    siteContent={siteContent}
                    onSave={handleSaveSiteContent}
                    onPreviewStorefront={switchToStorefront}
                    onNavigateOrders={() => setActiveTab('orders')}
                    pendingReceiptsCount={
                      orders.filter(
                        (o) =>
                          o.paymentStatus === 'PendingVerification' ||
                          Boolean(o.receiptImageUrl && o.paymentStatus !== 'Paid')
                      ).length
                    }
                  />
                )}

                {activeTab === 'page-editor' && siteContent && (
                  <PageEditorView
                    siteContent={siteContent}
                    onSave={handleSaveSiteContent}
                    onReset={handleResetSiteContent}
                    onPreviewStorefront={switchToStorefront}
                  />
                )}

                {activeTab === 'seo' && siteContent && (
                  <SeoManagementView
                    products={products}
                    categories={productCategories}
                    posts={posts}
                    siteContent={siteContent}
                    onSaveSiteContent={handleSaveSiteContent}
                    onNavigateTab={setActiveTab}
                  />
                )}

                {activeTab === 'search-engines' && siteContent && (
                  <SearchEnginesView
                    siteContent={siteContent}
                    products={products}
                    onSaveSiteContent={handleSaveSiteContent}
                    onNavigateTab={setActiveTab}
                    onPreviewStorefront={switchToStorefront}
                  />
                )}

                {activeTab === 'bot' && (
                  <BotSettingsView
                    config={botConfig}
                    logs={botLogs}
                    messages={messages}
                    orders={orders}
                    siteContent={siteContent}
                    onUpdateConfig={handleUpdateBotConfig}
                    onSimulateEvent={handleSimulateBotEvent}
                    onRespondMessage={handleRespondMessage}
                    onNavigate={setActiveTab}
                    onRefreshData={fetchData}
                  />
                )}

                {activeTab === 'account' && (
                  <AccountView
                    siteContent={siteContent || undefined}
                    onUpdateSiteContent={async (c) => {
                      await handleSaveSiteContent(c);
                      return true;
                    }}
                    onRefreshData={fetchData}
                    initialSetupCompleted={initialSetupCompleted}
                    onSetupCompleted={handleSetupCompletedFlow}
                  />
                )}
              </>
            )}
          </div>
        </main>
      </div>
    </div>
    </ErrorBoundary>
  );
}
