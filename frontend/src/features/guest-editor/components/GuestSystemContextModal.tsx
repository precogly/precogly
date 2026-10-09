import { useState, useCallback } from 'react'
import {
  Users,
  FileText,
  Package,
  ClipboardList,
  ShieldX,
  Plus,
  Trash2,
  Pencil,
  X,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useGuestEditor } from '../context/GuestEditorContext'
import {
  GUEST_CRITICALITY_OPTIONS,
  GUEST_CIA_LEVELS,
  GUEST_ASSUMPTION_VALIDITY,
} from '../types'
import type { GuestDataAsset, GuestAssumption, GuestOutOfScopeItem } from '../types'
import { ASSUMPTION_TOPICS } from '@/types/domain'

type ContextView = 'session' | 'system' | 'assets' | 'assumptions' | 'out-of-scope'

interface GuestSystemContextModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

function ContextButton({
  icon: Icon,
  label,
  count,
  active,
  onClick,
}: {
  icon: React.ElementType
  label: string
  count?: number
  active: boolean
  onClick: () => void
}) {
  return (
    <Button
      variant="outline"
      className={`relative h-auto py-3 px-4 flex flex-col items-center gap-2 ${
        active ? 'border-amber-500 border-2 bg-amber-50' : ''
      }`}
      onClick={onClick}
    >
      <Icon className="h-5 w-5" />
      <span className="text-xs">{label}</span>
      {count !== undefined && count > 0 && (
        <span className="absolute -top-2 -right-2 bg-amber-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
          {count}
        </span>
      )}
    </Button>
  )
}

// --- Session View ---
function SessionView() {
  const guestEditor = useGuestEditor()
  const [participantInput, setParticipantInput] = useState('')

  if (!guestEditor) return null

  const handleAddParticipant = () => {
    const trimmed = participantInput.trim()
    if (trimmed && !guestEditor.session.participants.includes(trimmed)) {
      guestEditor.updateSession({
        participants: [...guestEditor.session.participants, trimmed],
      })
      setParticipantInput('')
    }
  }

  const handleRemoveParticipant = (participant: string) => {
    guestEditor.updateSession({
      participants: guestEditor.session.participants.filter((p) => p !== participant),
    })
  }

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="facilitator">Facilitator</Label>
        <Input
          id="facilitator"
          value={guestEditor.session.facilitator}
          onChange={(e) => guestEditor.updateSession({ facilitator: e.target.value })}
          placeholder="Name of the session facilitator"
        />
      </div>

      <div className="space-y-2">
        <Label>Participants</Label>
        <div className="flex gap-2">
          <Input
            value={participantInput}
            onChange={(e) => setParticipantInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault()
                handleAddParticipant()
              }
            }}
            placeholder="Add participant name"
            className="flex-1"
          />
          <Button variant="outline" size="sm" onClick={handleAddParticipant}>
            <Plus className="h-4 w-4" />
          </Button>
        </div>
        {guestEditor.session.participants.length > 0 && (
          <div className="flex flex-wrap gap-2 mt-2">
            {guestEditor.session.participants.map((participant) => (
              <Badge key={participant} variant="secondary" className="gap-1">
                {participant}
                <button
                  onClick={() => handleRemoveParticipant(participant)}
                  className="ml-1 hover:text-destructive"
                >
                  <X className="h-3 w-3" />
                </button>
              </Badge>
            ))}
          </div>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="meeting-date">Meeting Date</Label>
        <Input
          id="meeting-date"
          type="date"
          value={guestEditor.session.meetingDate}
          onChange={(e) => guestEditor.updateSession({ meetingDate: e.target.value })}
        />
      </div>
    </div>
  )
}

// --- System View ---
function SystemView() {
  const guestEditor = useGuestEditor()
  if (!guestEditor) return null

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="system-description">System Description</Label>
        <Textarea
          id="system-description"
          rows={6}
          value={guestEditor.systemInfo.description}
          onChange={(e) => guestEditor.updateSystemInfo({ description: e.target.value })}
          placeholder="Describe the system being threat modeled..."
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="criticality">Criticality</Label>
        <Select
          value={guestEditor.systemInfo.criticality}
          onValueChange={(value) =>
            guestEditor.updateSystemInfo({ criticality: value as GuestDataAsset['confidentiality'] })
          }
        >
          <SelectTrigger id="criticality">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {GUEST_CRITICALITY_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </div>
  )
}

// --- Assets View ---
function AssetsView() {
  const guestEditor = useGuestEditor()
  const [showAddForm, setShowAddForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [formData, setFormData] = useState<Omit<GuestDataAsset, 'id'>>({
    name: '',
    description: '',
    classification: 'internal',
    confidentiality: 'medium',
    integrity: 'medium',
    availability: 'medium',
    complianceTags: [],
    dataSensitivity: [],
  })
  const [complianceInput, setComplianceInput] = useState('')
  const [sensitivityInput, setSensitivityInput] = useState('')

  if (!guestEditor) return null

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      classification: 'internal',
      confidentiality: 'medium',
      integrity: 'medium',
      availability: 'medium',
      complianceTags: [],
      dataSensitivity: [],
    })
    setComplianceInput('')
    setSensitivityInput('')
    setShowAddForm(false)
    setEditingId(null)
  }

  const handleSave = () => {
    if (!formData.name.trim()) return
    if (editingId) {
      guestEditor.updateDataAsset(editingId, formData)
    } else {
      guestEditor.addDataAsset(formData)
    }
    resetForm()
  }

  const handleEdit = (asset: GuestDataAsset) => {
    setFormData({
      name: asset.name,
      description: asset.description,
      classification: asset.classification,
      confidentiality: asset.confidentiality,
      integrity: asset.integrity,
      availability: asset.availability,
      complianceTags: asset.complianceTags,
      dataSensitivity: asset.dataSensitivity,
      ...(asset.bomRef ? { bomRef: asset.bomRef } : {}),
      ...(asset.passthrough ? { passthrough: asset.passthrough } : {}),
    })
    setComplianceInput('')
    setSensitivityInput('')
    setEditingId(asset.id)
    setShowAddForm(true)
  }

  const handleAddComplianceTag = () => {
    const trimmed = complianceInput.trim()
    if (trimmed && !formData.complianceTags.includes(trimmed)) {
      setFormData({ ...formData, complianceTags: [...formData.complianceTags, trimmed] })
      setComplianceInput('')
    }
  }

  const handleAddSensitivityTag = () => {
    const trimmed = sensitivityInput.trim()
    if (trimmed && !formData.dataSensitivity.includes(trimmed)) {
      setFormData({ ...formData, dataSensitivity: [...formData.dataSensitivity, trimmed] })
      setSensitivityInput('')
    }
  }

  return (
    <div className="space-y-4">
      {/* Existing assets list */}
      {guestEditor.dataAssets.length > 0 && (
        <div className="space-y-2 max-h-[200px] overflow-y-auto">
          {guestEditor.dataAssets.map((asset) => (
            <div
              key={asset.id}
              className="flex items-center justify-between p-2 rounded border bg-muted/30"
            >
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{asset.name}</p>
                <p className="text-xs text-muted-foreground truncate">
                  {asset.classification} | C:{asset.confidentiality} I:{asset.integrity} A:{asset.availability}
                </p>
              </div>
              <div className="flex items-center gap-1 ml-2">
                <Button variant="ghost" size="sm" onClick={() => handleEdit(asset)}>
                  Edit
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => guestEditor.removeDataAsset(asset.id)}
                >
                  <Trash2 className="h-3.5 w-3.5 text-destructive" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add/Edit form */}
      {showAddForm ? (
        <div className="space-y-3 border rounded p-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label className="text-xs">Name</Label>
              <Input
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="Asset name"
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Classification</Label>
              <Select
                value={formData.classification}
                onValueChange={(value) => setFormData({ ...formData, classification: value })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="public">Public</SelectItem>
                  <SelectItem value="internal">Internal</SelectItem>
                  <SelectItem value="confidential">Confidential</SelectItem>
                  <SelectItem value="restricted">Restricted</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-1">
            <Label className="text-xs">Description</Label>
            <Textarea
              rows={2}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="Brief description of the data asset"
            />
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div className="space-y-1">
              <Label className="text-xs">Confidentiality</Label>
              <Select
                value={formData.confidentiality}
                onValueChange={(value) =>
                  setFormData({ ...formData, confidentiality: value as 'low' | 'medium' | 'high' })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {GUEST_CIA_LEVELS.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Integrity</Label>
              <Select
                value={formData.integrity}
                onValueChange={(value) =>
                  setFormData({ ...formData, integrity: value as 'low' | 'medium' | 'high' })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {GUEST_CIA_LEVELS.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Availability</Label>
              <Select
                value={formData.availability}
                onValueChange={(value) =>
                  setFormData({ ...formData, availability: value as 'low' | 'medium' | 'high' })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {GUEST_CIA_LEVELS.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-1">
            <Label className="text-xs">Compliance Tags</Label>
            <div className="flex gap-2">
              <Input
                value={complianceInput}
                onChange={(e) => setComplianceInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    handleAddComplianceTag()
                  }
                }}
                placeholder="e.g., GDPR, SOC2"
                className="flex-1"
              />
              <Button variant="outline" size="sm" onClick={handleAddComplianceTag}>
                <Plus className="h-3 w-3" />
              </Button>
            </div>
            {formData.complianceTags.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1">
                {formData.complianceTags.map((tag) => (
                  <Badge key={tag} variant="secondary" className="text-xs gap-1">
                    {tag}
                    <button
                      onClick={() =>
                        setFormData({
                          ...formData,
                          complianceTags: formData.complianceTags.filter((t) => t !== tag),
                        })
                      }
                    >
                      <X className="h-2.5 w-2.5" />
                    </button>
                  </Badge>
                ))}
              </div>
            )}
          </div>

          <div className="space-y-1">
            <Label className="text-xs">Sensitivity Tags</Label>
            <div className="flex gap-2">
              <Input
                value={sensitivityInput}
                onChange={(e) => setSensitivityInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    handleAddSensitivityTag()
                  }
                }}
                placeholder="e.g., PII, PHI"
                className="flex-1"
              />
              <Button variant="outline" size="sm" onClick={handleAddSensitivityTag}>
                <Plus className="h-3 w-3" />
              </Button>
            </div>
            {formData.dataSensitivity.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1">
                {formData.dataSensitivity.map((tag) => (
                  <Badge key={tag} variant="secondary" className="text-xs gap-1">
                    {tag}
                    <button
                      onClick={() =>
                        setFormData({
                          ...formData,
                          dataSensitivity: formData.dataSensitivity.filter((t) => t !== tag),
                        })
                      }
                    >
                      <X className="h-2.5 w-2.5" />
                    </button>
                  </Badge>
                ))}
              </div>
            )}
          </div>

          <div className="flex justify-end gap-2">
            <Button variant="outline" size="sm" onClick={resetForm}>
              Cancel
            </Button>
            <Button size="sm" onClick={handleSave} disabled={!formData.name.trim()}>
              {editingId ? 'Update' : 'Add'} Asset
            </Button>
          </div>
        </div>
      ) : (
        <Button variant="outline" size="sm" onClick={() => setShowAddForm(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Add Data Asset
        </Button>
      )}
    </div>
  )
}

// --- Assumptions View ---
function AssumptionsView() {
  const guestEditor = useGuestEditor()
  const [showAddForm, setShowAddForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [formData, setFormData] = useState<Omit<GuestAssumption, 'id'>>({
    description: '',
    validity: 'unverified',
    topic: '',
  })

  if (!guestEditor) return null

  const resetForm = () => {
    setFormData({ description: '', validity: 'unverified', topic: '' })
    setShowAddForm(false)
    setEditingId(null)
  }

  const handleSave = () => {
    if (!formData.description.trim()) return
    if (editingId) {
      guestEditor.updateAssumption(editingId, formData)
    } else {
      guestEditor.addAssumption(formData)
    }
    resetForm()
  }

  const handleEdit = (assumption: GuestAssumption) => {
    setFormData({
      description: assumption.description,
      validity: assumption.validity,
      topic: assumption.topic,
      ...(assumption.bomRef ? { bomRef: assumption.bomRef } : {}),
      ...(assumption.passthrough ? { passthrough: assumption.passthrough } : {}),
    })
    setEditingId(assumption.id)
    setShowAddForm(true)
  }

  const validityLabel = (validity: GuestAssumption['validity']) =>
    GUEST_ASSUMPTION_VALIDITY.find((o) => o.value === validity)?.label ?? validity

  const topicLabel = (topic: string) => ASSUMPTION_TOPICS.find((o) => o.value === topic)?.label ?? topic

  return (
    <div className="space-y-4">
      {/* Existing assumptions list */}
      {guestEditor.assumptions.length > 0 && (
        <div className="space-y-2 max-h-[250px] overflow-y-auto">
          {guestEditor.assumptions.map((assumption) => (
            <div
              key={assumption.id}
              className="flex items-center justify-between p-2 rounded border bg-muted/30"
            >
              <div className="flex-1 min-w-0 space-y-1">
                <p className="text-sm">{assumption.description}</p>
                <div className="flex flex-wrap items-center gap-1">
                  <Badge variant="outline" className="text-xs">
                    {validityLabel(assumption.validity)}
                  </Badge>
                  {assumption.topic && (
                    <Badge variant="secondary" className="text-xs">
                      {topicLabel(assumption.topic)}
                    </Badge>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-1 ml-2">
                <Button variant="ghost" size="sm" onClick={() => handleEdit(assumption)}>
                  Edit
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => guestEditor.removeAssumption(assumption.id)}
                >
                  <Trash2 className="h-3.5 w-3.5 text-destructive" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add/Edit form */}
      {showAddForm ? (
        <div className="space-y-3 border rounded p-3">
          <div className="space-y-1">
            <Label className="text-xs">Description *</Label>
            <Textarea
              rows={2}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="Describe the assumption..."
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label className="text-xs">Validity</Label>
              <Select
                value={formData.validity}
                onValueChange={(value) =>
                  setFormData({ ...formData, validity: value as GuestAssumption['validity'] })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {GUEST_ASSUMPTION_VALIDITY.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Topic</Label>
              <Select
                value={formData.topic || 'none'}
                onValueChange={(value) => setFormData({ ...formData, topic: value === 'none' ? '' : value })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None</SelectItem>
                  {ASSUMPTION_TOPICS.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="flex justify-end gap-2">
            <Button variant="outline" size="sm" onClick={resetForm}>
              Cancel
            </Button>
            <Button size="sm" onClick={handleSave} disabled={!formData.description.trim()}>
              {editingId ? 'Update' : 'Add'} Assumption
            </Button>
          </div>
        </div>
      ) : (
        <Button variant="outline" size="sm" onClick={() => setShowAddForm(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Add Assumption
        </Button>
      )}
    </div>
  )
}

// --- Out of Scope View ---
function OutOfScopeView() {
  const guestEditor = useGuestEditor()
  const [newName, setNewName] = useState('')
  const [newReason, setNewReason] = useState('')
  const [editingId, setEditingId] = useState<string | null>(null)

  if (!guestEditor) return null

  const handleAdd = () => {
    if (!newName.trim()) return
    const item = { name: newName.trim(), reason: newReason.trim() }
    if (editingId) {
      guestEditor.updateOutOfScopeItem(editingId, item)
    } else {
      guestEditor.addOutOfScopeItem(item)
    }
    setNewName('')
    setNewReason('')
    setEditingId(null)
  }

  const handleEdit = (item: GuestOutOfScopeItem) => {
    setEditingId(item.id)
    setNewName(item.name)
    setNewReason(item.reason)
  }

  const handleCancelEdit = () => {
    setEditingId(null)
    setNewName('')
    setNewReason('')
  }

  return (
    <div className="space-y-4">
      {/* Existing items */}
      {guestEditor.outOfScopeItems.length > 0 && (
        <div className="space-y-2 max-h-[250px] overflow-y-auto">
          {guestEditor.outOfScopeItems.map((item) => (
            <div
              key={item.id}
              className="flex items-center justify-between p-2 rounded border bg-muted/30"
            >
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium">{item.name}</p>
                {item.reason && (
                  <p className="text-xs text-muted-foreground">{item.reason}</p>
                )}
              </div>
              <div className="flex items-center gap-1 ml-2">
                <Button variant="ghost" size="sm" onClick={() => handleEdit(item)}>
                  <Pencil className="h-3.5 w-3.5" />
                  <span className="sr-only">Edit {item.name}</span>
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => guestEditor.removeOutOfScopeItem(item.id)}
                >
                  <Trash2 className="h-3.5 w-3.5 text-destructive" />
                  <span className="sr-only">Delete {item.name}</span>
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add form */}
      <div className="border rounded p-3 space-y-2">
        <Input
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          placeholder="Item name"
        />
        <Input
          value={newReason}
          onChange={(e) => setNewReason(e.target.value)}
          placeholder="Reason for exclusion"
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault()
              handleAdd()
            }
          }}
        />
        <Button variant="outline" size="sm" onClick={handleAdd} disabled={!newName.trim()}>
          {editingId ? 'Update Item' : 'Add Item'}
        </Button>
        {editingId && (
          <Button variant="ghost" size="sm" onClick={handleCancelEdit}>
            Cancel
          </Button>
        )}
      </div>
    </div>
  )
}

// --- Main Modal ---
export function GuestSystemContextModal({ open, onOpenChange }: GuestSystemContextModalProps) {
  const guestEditor = useGuestEditor()
  const [activeView, setActiveView] = useState<ContextView>('session')

  const getSessionCount = useCallback(() => {
    if (!guestEditor) return 0
    let count = 0
    if (guestEditor.session.facilitator) count++
    count += guestEditor.session.participants.length
    if (guestEditor.session.meetingDate) count++
    return count
  }, [guestEditor])

  const getSystemCount = useCallback(() => {
    if (!guestEditor) return 0
    return guestEditor.systemInfo.description ? 1 : 0
  }, [guestEditor])

  if (!guestEditor) return null

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>System Context</DialogTitle>
          <DialogDescription>
            Define session metadata, system information, data assets, assumptions, and scope exclusions.
          </DialogDescription>
        </DialogHeader>

        {/* Context buttons grid */}
        <div className="grid grid-cols-5 gap-3">
          <ContextButton
            icon={Users}
            label="Session"
            count={getSessionCount()}
            active={activeView === 'session'}
            onClick={() => setActiveView('session')}
          />
          <ContextButton
            icon={FileText}
            label="System"
            count={getSystemCount()}
            active={activeView === 'system'}
            onClick={() => setActiveView('system')}
          />
          <ContextButton
            icon={Package}
            label="Assets"
            count={guestEditor.dataAssets.length}
            active={activeView === 'assets'}
            onClick={() => setActiveView('assets')}
          />
          <ContextButton
            icon={ClipboardList}
            label="Assumptions"
            count={guestEditor.assumptions.length}
            active={activeView === 'assumptions'}
            onClick={() => setActiveView('assumptions')}
          />
          <ContextButton
            icon={ShieldX}
            label="Out of Scope"
            count={guestEditor.outOfScopeItems.length}
            active={activeView === 'out-of-scope'}
            onClick={() => setActiveView('out-of-scope')}
          />
        </div>

        {/* Content area */}
        <div className="mt-4">
          {activeView === 'session' && <SessionView />}
          {activeView === 'system' && <SystemView />}
          {activeView === 'assets' && <AssetsView />}
          {activeView === 'assumptions' && <AssumptionsView />}
          {activeView === 'out-of-scope' && <OutOfScopeView />}
        </div>
      </DialogContent>
    </Dialog>
  )
}
