/**
 * Team management page with create, edit, delete, and member role management.
 */

import { useState } from 'react'
import { useWorkspace } from '@/contexts/WorkspaceContext'
import {
  useTeams,
  useTeamMembers,
  useCreateTeam,
  useUpdateTeam,
  useDeleteTeam,
  useInviteTeamMember,
  useRemoveTeamMember,
  useChangeTeamMemberRole,
  useBusinessUnits,
  useOrganizationMembers,
} from '@/features/organization/api/organizations'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { UserPlus, Trash2, Plus, Pencil, Loader2, Copy, Check } from 'lucide-react'
import type { TeamListItem, TeamRole, InviteMemberResponse } from '@/features/organization/types/organization'

export function TeamManagement() {
  const { currentOrganization, isLoading: workspaceLoading, isSecurityTeam } = useWorkspace()
  const { data: teams = [], isLoading: teamsLoading } = useTeams(currentOrganization?.id)
  const { data: businessUnits = [] } = useBusinessUnits(currentOrganization?.id)
  const createTeamMutation = useCreateTeam()
  const updateTeamMutation = useUpdateTeam()
  const deleteTeamMutation = useDeleteTeam()

  const [selectedTeam, setSelectedTeam] = useState<TeamListItem | null>(null)
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [editingTeam, setEditingTeam] = useState<TeamListItem | null>(null)

  // Create team form state
  const [newTeamName, setNewTeamName] = useState('')
  const [newTeamCode, setNewTeamCode] = useState('')
  const [newTeamDescription, setNewTeamDescription] = useState('')
  const [newTeamBusinessUnit, setNewTeamBusinessUnit] = useState<string>('')

  // Edit team form state
  const [editName, setEditName] = useState('')
  const [editDescription, setEditDescription] = useState('')

  if (workspaceLoading || teamsLoading) {
    return <div>Loading...</div>
  }

  if (!currentOrganization) {
    return <div>No organization selected.</div>
  }

  const handleCreateTeam = () => {
    if (!newTeamName.trim()) return
    createTeamMutation.mutate(
      {
        organization: currentOrganization.id,
        name: newTeamName,
        code: newTeamCode || undefined,
        description: newTeamDescription || undefined,
        businessUnit: newTeamBusinessUnit ? parseInt(newTeamBusinessUnit, 10) : undefined,
      },
      {
        onSuccess: () => {
          setShowCreateDialog(false)
          setNewTeamName('')
          setNewTeamCode('')
          setNewTeamDescription('')
          setNewTeamBusinessUnit('')
        },
      }
    )
  }

  const handleEditTeam = () => {
    if (!editingTeam || !editName.trim()) return
    updateTeamMutation.mutate(
      { id: editingTeam.id, data: { name: editName, description: editDescription } },
      {
        onSuccess: () => setEditingTeam(null),
      }
    )
  }

  const handleDeleteTeam = (teamId: number, teamName: string) => {
    if (!confirm(`Are you sure you want to delete "${teamName}"? This cannot be undone.`)) return
    deleteTeamMutation.mutate(teamId)
  }

  const openEditDialog = (team: TeamListItem) => {
    setEditingTeam(team)
    setEditName(team.name)
    setEditDescription(team.description ?? '')
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Teams</CardTitle>
              <CardDescription>
                Manage teams in {currentOrganization.name}.
              </CardDescription>
            </div>
            <Button onClick={() => setShowCreateDialog(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Create Team
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {teams.length === 0 ? (
            <p className="text-muted-foreground">No teams found.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Team Name</TableHead>
                  <TableHead>{currentOrganization.businessUnitLabel}</TableHead>
                  <TableHead>Members</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {teams.map((team) => (
                  <TableRow key={team.id}>
                    <TableCell className="font-medium">
                      {team.name}
                      {team.isDefault && (
                        <Badge variant="outline" className="ml-2">
                          Default
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {team.businessUnitName ?? '-'}
                    </TableCell>
                    <TableCell>{team.memberCount}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setSelectedTeam(team)}
                          disabled={!team.isMember && !isSecurityTeam}
                        >
                          Manage
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8"
                          onClick={() => openEditDialog(team)}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-destructive hover:text-destructive"
                          onClick={() => handleDeleteTeam(team.id, team.name)}
                          disabled={deleteTeamMutation.isPending}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Create Team Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Team</DialogTitle>
            <DialogDescription>Add a new team to your organization.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="team-name">Name</Label>
              <Input
                id="team-name"
                value={newTeamName}
                onChange={(e) => setNewTeamName(e.target.value)}
                placeholder="e.g., Platform Security"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="team-code">Code (optional)</Label>
              <Input
                id="team-code"
                value={newTeamCode}
                onChange={(e) => setNewTeamCode(e.target.value)}
                placeholder="e.g., PLAT-SEC"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="team-desc">Description (optional)</Label>
              <Textarea
                id="team-desc"
                value={newTeamDescription}
                onChange={(e) => setNewTeamDescription(e.target.value)}
                rows={2}
              />
            </div>
            {businessUnits.length > 0 && (
              <div className="space-y-2">
                <Label>{currentOrganization.businessUnitLabel}</Label>
                <Select value={newTeamBusinessUnit} onValueChange={setNewTeamBusinessUnit}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select (optional)" />
                  </SelectTrigger>
                  <SelectContent>
                    {businessUnits.map((bu) => (
                      <SelectItem key={bu.id} value={bu.id.toString()}>
                        {bu.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreateTeam} disabled={!newTeamName.trim() || createTeamMutation.isPending}>
              {createTeamMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Team Dialog */}
      <Dialog open={!!editingTeam} onOpenChange={(open) => !open && setEditingTeam(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Team</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Name</Label>
              <Input value={editName} onChange={(e) => setEditName(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Description</Label>
              <Textarea value={editDescription} onChange={(e) => setEditDescription(e.target.value)} rows={2} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingTeam(null)}>Cancel</Button>
            <Button onClick={handleEditTeam} disabled={!editName.trim() || updateTeamMutation.isPending}>
              {updateTeamMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Team Members Dialog */}
      {selectedTeam && (
        <TeamMembersDialog
          team={selectedTeam}
          open={!!selectedTeam}
          onOpenChange={(open) => !open && setSelectedTeam(null)}
        />
      )}
    </div>
  )
}

interface TeamMembersDialogProps {
  team: TeamListItem
  open: boolean
  onOpenChange: (open: boolean) => void
}

function TeamMembersDialog({ team, open, onOpenChange }: TeamMembersDialogProps) {
  const { data: members = [], isLoading } = useTeamMembers(team.id)
  const { currentOrganization } = useWorkspace()

  const { data: orgMembers = [] } =
    useOrganizationMembers(currentOrganization?.id ?? 0)
  
  const availableOrgMembers = orgMembers.filter(
  (orgMember) =>
    !members.some(
      (teamMember) => teamMember.user === orgMember.user
    )
)

  const { mutate: inviteMember, isPending: isInviting } = useInviteTeamMember()
  const { mutate: removeMember, isPending: isRemoving } = useRemoveTeamMember()
  const { mutate: changeRole, isPending: isChangingRole } = useChangeTeamMemberRole()

  const [inviteEmail, setInviteEmail] = useState('')
  const [selectedOrgMember, setSelectedOrgMember] = useState('')
  const [addRole, setAddRole] = useState<TeamRole>('member')
  const [inviteRole, setInviteRole] = useState<TeamRole>('member')
  const [inviteResult, setInviteResult] = useState<InviteMemberResponse | null>(null)
  const [copiedLink, setCopiedLink] = useState(false)

  const roleColors: Record<string, string> = {
    lead: 'bg-purple-100 text-purple-800',
    member: 'bg-blue-100 text-blue-800',
    viewer: 'bg-gray-100 text-gray-800',
  }

  const handleInvite = () => {
    console.log("handleAddExisting called")
    if (!inviteEmail) return
    setInviteResult(null)
    inviteMember(
      { teamId: team.id, email: inviteEmail, role: addRole, },
      {
        onSuccess: (data) => {
          setInviteEmail('')
          setAddRole('member')
          setInviteResult(data)
        },
      }
    )
  }

  const handleAddExisting = () => {

  if (!selectedOrgMember) return

  const member = orgMembers.find(
    (m) => m.user === parseInt(selectedOrgMember, 10)
  )

  console.log(member)

  if (!member) return

  setInviteResult(null)

  inviteMember(
    {
      teamId: team.id,
      email: member.userEmail,
      role: inviteRole,
    },
    {
      onSuccess: (data) => {
        console.log("SUCCESS")
        setSelectedOrgMember('')
        setInviteRole('member')
        setInviteResult(data)
      },
    }
  )
}

  const handleCopyInviteLink = () => {
    if (!inviteResult?.invitation?.inviteUrl) return
    const fullUrl = `${window.location.origin}${inviteResult.invitation.inviteUrl}`
    navigator.clipboard.writeText(fullUrl)
    setCopiedLink(true)
    setTimeout(() => setCopiedLink(false), 2000)
  }

  const handleRemove = (userId: number) => {
    if (confirm('Are you sure you want to remove this member from the team?')) {
      removeMember({ teamId: team.id, userId })
    }
  }

  const handleRoleChange = (userId: number, newRole: string) => {
    changeRole({ teamId: team.id, userId, role: newRole })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Manage Team: {team.name}</DialogTitle>
          <DialogDescription>
            Add, remove, or change roles of team members.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 min-w-0">
          {/* Invite form */}
          <div className="space-y-2 min-w-0">
          {availableOrgMembers.length > 0 && (
            <div className="space-y-2">
              <Label>Add Existing Member</Label>
              <div className="flex gap-2">
                <Select
                  value={selectedOrgMember}
                  onValueChange={setSelectedOrgMember}
                >
                  <SelectTrigger className="flex-1">
                    <SelectValue placeholder="Select a member..." />
                  </SelectTrigger>
                  <SelectContent>
                    {availableOrgMembers.map((member) => (
                      <SelectItem
                        key={member.user}
                        value={member.user.toString()}
                      >
                        {member.userEmail}
                      </SelectItem>
                  ))}
                  </SelectContent>
                </Select>
                <Select value={addRole} onValueChange={(value) => setAddRole(value as TeamRole)}>
                  <SelectTrigger className="w-28">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="lead">Lead</SelectItem>
                    <SelectItem value="member">Member</SelectItem>
                    <SelectItem value="viewer">Viewer</SelectItem>
                  </SelectContent>
                </Select>

    <Button
  onClick={handleAddExisting}
  disabled={isInviting || !selectedOrgMember}
>
  <UserPlus className="h-4 w-4" />
</Button>
  </div>
</div>
            )}
            <Label>Or Invite by Email</Label>
            <div className="flex gap-2">
              <Input
                type="email"
                placeholder="Email address"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                className="flex-1 min-w-0"
              />
              <Select
                value={inviteRole}
                onValueChange={(value) => setInviteRole(value as TeamRole)}
              >
                <SelectTrigger className="w-28">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="lead">Lead</SelectItem>
                  <SelectItem value="member">Member</SelectItem>
                  <SelectItem value="viewer">Viewer</SelectItem>
                </SelectContent>
              </Select>
              <Button onClick={handleInvite} disabled={isInviting || !inviteEmail}>
                <UserPlus className="h-4 w-4" />
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              If the user doesn't have an account, they'll receive an invite link.
            </p>
            {inviteResult && (
              <div className="p-3 rounded-md bg-muted text-sm min-w-0">
                {inviteResult.status === 'added' ? (
                  <p className="flex items-center gap-2">
                    <Check className="h-4 w-4 text-green-600" />
                    Member added to the team.
                  </p>
                ) : inviteResult.invitation ? (
                  <div className="space-y-2 min-w-0">
                    <p>Invitation created for <span className="font-medium">{inviteResult.invitation.email}</span>. Share this link with them:</p>
                    <div className="flex items-center gap-2 min-w-0">
                      <code className="flex-1 min-w-0 text-xs bg-background p-2 rounded border break-all">
                        {`${window.location.origin}${inviteResult.invitation.inviteUrl}`}
                      </code>
                      <Button variant="outline" size="sm" onClick={handleCopyInviteLink} className="shrink-0">
                        {copiedLink ? <Check className="h-4 w-4 text-green-600" /> : <Copy className="h-4 w-4" />}
                      </Button>
                    </div>
                  </div>
                ) : null}
              </div>
            )}
          </div>

          {/* Members list */}
          <div className="space-y-2">
            <Label>Current Members</Label>
            {isLoading ? (
              <p className="text-muted-foreground text-sm">Loading...</p>
            ) : members.length === 0 ? (
              <p className="text-muted-foreground text-sm">No members yet.</p>
            ) : (
              <div className="border rounded-md divide-y max-h-60 overflow-y-auto">
                {members.map((member) => (
                  <div
                    key={member.id}
                    className="flex items-center justify-between p-2"
                  >
                    <div>
                      <p className="font-medium text-sm">{member.userName}</p>
                      <p className="text-xs text-muted-foreground">{member.userEmail}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Select
                        value={member.role}
                        onValueChange={(value) => handleRoleChange(member.user, value)}
                        disabled={isChangingRole}
                      >
                        <SelectTrigger className="w-28 h-8">
                          <Badge className={roleColors[member.role]}>
                            {member.role}
                          </Badge>
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="lead">Lead</SelectItem>
                          <SelectItem value="member">Member</SelectItem>
                          <SelectItem value="viewer">Viewer</SelectItem>
                        </SelectContent>
                      </Select>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-destructive hover:text-destructive"
                        onClick={() => handleRemove(member.user)}
                        disabled={isRemoving}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
