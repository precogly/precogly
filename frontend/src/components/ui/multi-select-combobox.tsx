import { useState } from 'react'
import { Check, ChevronsUpDown, X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { normalizeTags } from '@/lib/normalize-tags'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'

export interface ComboboxOption {
  value: string
  label: string
  description?: string
  meta?: string
}

interface MultiSelectComboboxProps {
  options: ComboboxOption[]
  selected: string[]
  onChange: (selected: string[]) => void
  placeholder?: string
  searchPlaceholder?: string
  emptyMessage?: string
  className?: string
  allowCustom?: boolean
}

export function MultiSelectCombobox({
  options,
  selected,
  onChange,
  placeholder = 'Select items...',
  searchPlaceholder = 'Search...',
  emptyMessage = 'No items found.',
  className,
  allowCustom = false,
}: MultiSelectComboboxProps) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')

  // Build chip display list: known options + fallback for custom values
  const selectedChips = selected.map((val) => {
    const knownOption = options.find((o) => o.value === val)
    return knownOption ?? { value: val, label: val }
  })

  const toggleOption = (value: string) => {
    if (selected.includes(value)) {
      onChange(selected.filter((v) => v !== value))
    } else {
      onChange([...selected, value])
    }
  }

  const removeOption = (value: string, e: React.MouseEvent) => {
    e.stopPropagation()
    onChange(selected.filter((v) => v !== value))
  }

  const handleAddCustom = () => {
    const normalized = normalizeTags([search])[0]
    if (normalized && !selected.includes(normalized)) {
      onChange([...selected, normalized])
    }
    setSearch('')
  }

  const showCustomOption =
    allowCustom &&
    search.trim() !== '' &&
    !options.some((o) => o.value === search.trim().toLowerCase()) &&
    !selected.includes(search.trim().toLowerCase())

  return (
    <div className={cn('space-y-2', className)}>
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="outline"
            role="combobox"
            aria-expanded={open}
            className="w-full justify-between font-normal"
          >
            <span className="text-muted-foreground">
              {selected.length > 0
                ? `${selected.length} selected`
                : placeholder}
            </span>
            <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[var(--radix-popover-trigger-width)] p-0" align="start">
          <Command>
            <CommandInput
              placeholder={searchPlaceholder}
              value={search}
              onValueChange={setSearch}
            />
            <CommandList>
              <CommandEmpty>{emptyMessage}</CommandEmpty>
              <CommandGroup>
                {options.map((option) => (
                  <CommandItem
                    key={option.value}
                    value={option.label}
                    onSelect={() => toggleOption(option.value)}
                    className="cursor-pointer"
                  >
                    <div
                      className={cn(
                        'mr-2 flex h-4 w-4 items-center justify-center rounded-sm border border-primary',
                        selected.includes(option.value)
                          ? 'bg-primary text-primary-foreground'
                          : 'opacity-50 [&_svg]:invisible'
                      )}
                    >
                      <Check className="h-3 w-3" />
                    </div>
                    <div className="flex flex-col">
                      <span>
                        {option.label}
                        {option.meta && (
                          <span className="ml-2 text-xs text-muted-foreground">
                            ({option.meta})
                          </span>
                        )}
                      </span>
                      {option.description && (
                        <span className="text-xs text-muted-foreground">
                          {option.description}
                        </span>
                      )}
                    </div>
                  </CommandItem>
                ))}
              </CommandGroup>
              {showCustomOption && (
                <CommandGroup heading="Custom">
                  <CommandItem
                    value={`custom-${search}`}
                    onSelect={handleAddCustom}
                    className="cursor-pointer"
                  >
                    <Check className={cn('mr-2 h-4 w-4 opacity-0')} />
                    Use &quot;{search.trim()}&quot;
                  </CommandItem>
                </CommandGroup>
              )}
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>

      {/* Selected chips */}
      {selectedChips.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {selectedChips.map((option) => (
            <Badge
              key={option.value}
              variant="secondary"
              className="gap-1 pr-1"
            >
              {option.label}
              <button
                type="button"
                onClick={(e) => removeOption(option.value, e)}
                aria-label={`Remove ${option.label}`}
                className="ml-1 rounded-full outline-none ring-offset-background focus:ring-2 focus:ring-ring focus:ring-offset-2"
              >
                <X className="h-3 w-3 text-muted-foreground hover:text-foreground" />
              </button>
            </Badge>
          ))}
        </div>
      )}
    </div>
  )
}
