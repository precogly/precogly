import { createBrowserRouter, Navigate } from 'react-router-dom'
import { RootRoute } from '@/components/RootRoute'
import { GuestOnlyNotice } from '@/components/GuestOnlyNotice'
import {
  Dashboard,
  ThreatModels,
  ThreatModelDetail,
  Libraries,
  DFDEditor,
  GuestLayout,
  GuestDFDEditorPage,
  Login,
  Signup,
  ForgotPassword,
  ResetPassword,
  SharedThreatModelView,
  AcceptInvitation,
  SettingsLayout,
  ProfileSettings,
  OrganizationSettings,
  MemberManagement,
  TeamManagement,
  BusinessUnitsSettings,
  SystemsSettings,
  AIProviderSettings,
} from '@/pages'
import { lazy, Suspense } from 'react'

const GuestThreatAnalysis = lazy(() =>
  import('@/features/guest-editor/components/GuestThreatAnalysis').then((m) => ({
    default: m.GuestThreatAnalysis,
  }))
)

// When VITE_GUEST_ONLY is set, auth pages redirect to the guest editor
const isGuestOnly = import.meta.env.VITE_GUEST_ONLY === 'true'

export const router = createBrowserRouter([
  {
    path: '/login',
    element: isGuestOnly ? <GuestOnlyNotice /> : <Login />,
  },
  {
    path: '/signup',
    element: isGuestOnly ? <GuestOnlyNotice /> : <Signup />,
  },
  {
    path: '/forgot-password',
    element: isGuestOnly ? <GuestOnlyNotice /> : <ForgotPassword />,
  },
  {
    path: '/reset-password/:uid/:token',
    element: isGuestOnly ? <GuestOnlyNotice /> : <ResetPassword />,
  },
  // Public magic link route (no auth required)
  {
    path: '/share/:token',
    element: isGuestOnly ? <Navigate to="/" replace /> : <SharedThreatModelView />,
  },
  // Team invitation route (works for both logged-in and logged-out users)
  {
    path: '/invite/:token',
    element: isGuestOnly ? <Navigate to="/" replace /> : <AcceptInvitation />,
  },
  // Guest mode DFD editor (no auth required)
  {
    path: '/guest',
    element: <GuestLayout />,
    children: [
      { index: true, element: <GuestDFDEditorPage /> },
      { path: 'threats', element: <Suspense><GuestThreatAnalysis /></Suspense> },
    ],
  },
  {
    path: '/',
    element: <RootRoute />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'threat-models', element: <ThreatModels /> },
      { path: 'threat-models/new', element: <Navigate to="/threat-models" replace /> },
      { path: 'threat-models/:id', element: <ThreatModelDetail /> },
      { path: 'threat-models/:id/diagrams/:diagramId', element: <DFDEditor /> },
      // New unified Libraries page
      { path: 'libraries', element: <Libraries /> },
      // Legacy routes - redirect to Libraries page
      { path: 'frameworks', element: <Navigate to="/libraries" replace /> },
      { path: 'packs', element: <Navigate to="/libraries" replace /> },
      { path: 'packs/installed', element: <Navigate to="/libraries?tab=imported" replace /> },
      { path: 'tech-components', element: <Navigate to="/libraries" replace /> },
      { path: 'threat-libraries', element: <Navigate to="/libraries" replace /> },
      { path: 'countermeasures', element: <Navigate to="/libraries" replace /> },
      { path: 'dfd-templates', element: <Navigate to="/libraries" replace /> },
      // Settings routes
      {
        path: 'settings',
        element: <SettingsLayout />,
        children: [
          { index: true, element: <Navigate to="profile" replace /> },
          { path: 'profile', element: <ProfileSettings /> },
          { path: 'organization', element: <OrganizationSettings /> },
          { path: 'members', element: <MemberManagement /> },
          { path: 'teams', element: <TeamManagement /> },
          { path: 'business-units', element: <BusinessUnitsSettings /> },
          { path: 'systems', element: <SystemsSettings /> },
          { path: 'ai-providers', element: <AIProviderSettings /> },
        ],
      },
    ],
  },
])
