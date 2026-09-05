import React, { useRef, useState } from 'react';
import {
  TbChevronDown,
  TbChevronRight,
  TbFolderPlus,
  TbGripVertical,
  TbPencil,
  TbPlus,
  TbRestore,
  TbTrash,
} from 'react-icons/tb';
import { FilterPresetLibrary } from '../../types/packet';
import {
  DEFAULT_FILTER_PRESET_LIBRARY,
  addGroup,
  addPreset,
  allPresets,
  deleteGroup,
  deletePreset,
  moveGroup,
  movePreset,
  renameGroup,
  updatePreset,
} from '../../services/filterPresets';
import { FilterPresetEditor } from './FilterPresetEditor';

interface DisplayFiltersPanelProps {
  library: FilterPresetLibrary;
  onChange: (library: FilterPresetLibrary) => void;
}

/** What is currently being dragged. Groups and presets never mix as targets. */
type DragState =
  | { kind: 'preset'; presetId: string }
  | { kind: 'group'; groupId: string }
  | null;

/** Which slot the drop indicator is drawn in. */
type PresetDropTarget = { groupId: string; index: number } | null;

/** Which inline form, if any, is open. Only one at a time. */
type EditTarget =
  | { kind: 'new-preset'; groupId: string }
  | { kind: 'edit-preset'; presetId: string }
  | null;

/**
 * Settings > Display Filters: create, edit, delete and organise the display
 * filter presets that the Presets dropdown in the header offers.
 *
 * There is no Save button. Every edit is applied through `onChange`
 * immediately, which is what keeps this panel and the header dropdown showing
 * the same library at the same time - they read one piece of state in
 * App.tsx, and this panel is the only thing that writes it.
 *
 * Reordering uses the browser's own drag and drop rather than a library: the
 * hierarchy is one level deep and the drop targets are plain rows, which
 * HTML5 dnd handles without the weight of a dependency.
 */
export const DisplayFiltersPanel: React.FC<DisplayFiltersPanelProps> = ({ library, onChange }) => {
  // The whole drag lives in refs as well as in state, and the refs are what
  // the handlers read.
  //
  // Every step of a drag is a separate DOM event, and each one needs what the
  // step before it recorded: dragover needs to know what dragstart picked up,
  // and drop needs the slot dragover settled on. Reading those from state
  // means reading a render closure, which is only correct once React has
  // committed - so two events landing in the same task would see stale values
  // and the drop would silently do nothing. The state copies exist purely to
  // re-render the dimmed row and the drop indicator.
  const dragRef = useRef<DragState>(null);
  const presetDropRef = useRef<PresetDropTarget>(null);
  const groupDropRef = useRef<number | null>(null);
  const [drag, setDragState] = useState<DragState>(null);
  const [presetDrop, setPresetDropState] = useState<PresetDropTarget>(null);
  const [groupDrop, setGroupDropState] = useState<number | null>(null);

  const setDrag = (next: DragState) => {
    dragRef.current = next;
    setDragState(next);
  };
  const setPresetDrop = (next: PresetDropTarget) => {
    presetDropRef.current = next;
    setPresetDropState(next);
  };
  const setGroupDrop = (next: number | null) => {
    groupDropRef.current = next;
    setGroupDropState(next);
  };
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<EditTarget>(null);
  const [renamingGroupId, setRenamingGroupId] = useState<string | null>(null);
  const [renameDraft, setRenameDraft] = useState('');
  const [confirmRestore, setConfirmRestore] = useState(false);
  const [confirmDeleteGroupId, setConfirmDeleteGroupId] = useState<string | null>(null);

  const presetCount = allPresets(library).length;

  const toggleCollapsed = (groupId: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(groupId)) next.delete(groupId);
      else next.add(groupId);
      return next;
    });
  };

  const endDrag = () => {
    setDrag(null);
    setPresetDrop(null);
    setGroupDrop(null);
  };

  const handleAddGroup = () => {
    const next = addGroup(library, 'New group');
    onChange(next);
    // Drop straight into renaming it: a group called "New group" is never what
    // the user wanted, and this saves the extra trip to the pencil.
    const created = next.groups[next.groups.length - 1];
    setRenamingGroupId(created.id);
    setRenameDraft(created.name);
  };

  const commitRename = () => {
    if (renamingGroupId && renameDraft.trim()) {
      onChange(renameGroup(library, renamingGroupId, renameDraft.trim()));
    }
    setRenamingGroupId(null);
  };

  /**
   * An empty group goes immediately - there is nothing in it to lose, and
   * re-adding one is a single click. A group with filters in it asks first,
   * inline on its own header row rather than through window.confirm: a native
   * dialog is the one piece of UI in this app that cannot be themed, and it
   * would be the only one here.
   */
  const handleDeleteGroup = (groupId: string, presetCountInGroup: number) => {
    if (presetCountInGroup === 0) onChange(deleteGroup(library, groupId));
    else setConfirmDeleteGroupId(groupId);
  };

  // --- Drag handlers --------------------------------------------------------

  /**
   * Whether the pointer is in the upper or lower half of the row decides
   * whether the drop lands before or after it - the convention every list
   * reorder UI uses, and the reason a bare "drop on row" target feels
   * ambiguous.
   */
  const dropIndexForRow = (e: React.DragEvent, index: number): number => {
    const { top, height } = e.currentTarget.getBoundingClientRect();
    return e.clientY - top > height / 2 ? index + 1 : index;
  };

  const handlePresetRowDragOver = (e: React.DragEvent, groupId: string, index: number) => {
    if (dragRef.current?.kind !== 'preset') return;
    e.preventDefault();
    setPresetDrop({ groupId, index: dropIndexForRow(e, index) });
  };

  const handleGroupRowDragOver = (e: React.DragEvent, index: number) => {
    if (dragRef.current?.kind !== 'group') return;
    e.preventDefault();
    setGroupDrop(dropIndexForRow(e, index));
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const active = dragRef.current;
    const presetSlot = presetDropRef.current;
    const groupSlot = groupDropRef.current;
    if (active?.kind === 'preset' && presetSlot) {
      onChange(movePreset(library, active.presetId, presetSlot.groupId, presetSlot.index));
    } else if (active?.kind === 'group' && groupSlot !== null) {
      onChange(moveGroup(library, active.groupId, groupSlot));
    }
    endDrag();
  };

  // --- Render ---------------------------------------------------------------

  const iconButton =
    'p-1 rounded text-muted-foreground hover:text-foreground hover:bg-accent transition-colors cursor-pointer';

  return (
    <div className="flex flex-col gap-3 min-h-0">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-xs font-semibold text-foreground">Display filters</div>
          <p className="text-[11px] text-muted-foreground mt-0.5">
            Grouped exactly as they appear in the Presets dropdown. Drag a filter to reorder it or
            move it between groups.
          </p>
        </div>
        <span className="text-[10px] text-muted-foreground font-mono shrink-0 pt-0.5">
          {presetCount} filter{presetCount === 1 ? '' : 's'} / {library.groups.length} group
          {library.groups.length === 1 ? '' : 's'}
        </span>
      </div>

      <div
        className="flex flex-col gap-1.5 max-h-[22rem] overflow-y-auto custom-scrollbar pr-1"
        onDragEnd={endDrag}
        onDrop={handleDrop}
      >
        {library.groups.map((group, groupIndex) => {
          const isCollapsed = collapsed.has(group.id);
          const isRenaming = renamingGroupId === group.id;
          const isDraggingThisGroup = drag?.kind === 'group' && drag.groupId === group.id;

          return (
            <div
              key={group.id}
              onDragOver={(e) => handleGroupRowDragOver(e, groupIndex)}
              className={`rounded-md border transition-colors ${
                isDraggingThisGroup ? 'opacity-40 border-primary' : 'border-border'
              } ${
                drag?.kind === 'group' && groupDrop === groupIndex
                  ? 'border-t-2 border-t-primary'
                  : drag?.kind === 'group' && groupDrop === groupIndex + 1
                  ? 'border-b-2 border-b-primary'
                  : ''
              }`}
            >
              {/* Group header */}
              <div className="flex items-center gap-1 px-1.5 py-1.5 bg-muted/40 rounded-t-md">
                <span
                  draggable={!isRenaming}
                  onDragStart={() => setDrag({ kind: 'group', groupId: group.id })}
                  title="Drag to reorder group"
                  className="p-0.5 text-muted-foreground hover:text-foreground cursor-grab active:cursor-grabbing"
                >
                  <TbGripVertical className="w-3.5 h-3.5" />
                </span>

                <button
                  onClick={() => toggleCollapsed(group.id)}
                  className="p-0.5 rounded text-muted-foreground hover:text-foreground cursor-pointer"
                  title={isCollapsed ? 'Expand group' : 'Collapse group'}
                >
                  {isCollapsed ? (
                    <TbChevronRight className="w-3.5 h-3.5" />
                  ) : (
                    <TbChevronDown className="w-3.5 h-3.5" />
                  )}
                </button>

                {isRenaming ? (
                  <input
                    autoFocus
                    value={renameDraft}
                    onChange={(e) => setRenameDraft(e.target.value)}
                    onBlur={commitRename}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') commitRename();
                      else if (e.key === 'Escape') setRenamingGroupId(null);
                    }}
                    className="flex-1 min-w-0 rounded border border-primary bg-background px-1.5 py-0.5 text-xs font-semibold text-foreground outline-none"
                  />
                ) : (
                  <span className="flex-1 min-w-0 truncate text-xs font-semibold text-foreground">
                    {group.name}
                  </span>
                )}

                <span className="text-[10px] text-muted-foreground font-mono shrink-0">
                  {group.presets.length}
                </span>

                {confirmDeleteGroupId === group.id ? (
                  <div className="flex items-center gap-1.5 shrink-0">
                    <span className="text-[11px] text-muted-foreground">
                      Delete with {group.presets.length} filter{group.presets.length === 1 ? '' : 's'}?
                    </span>
                    <button
                      onClick={() => {
                        onChange(deleteGroup(library, group.id));
                        setConfirmDeleteGroupId(null);
                      }}
                      className="px-2 py-0.5 rounded bg-rose-600 hover:bg-rose-500 text-white text-[11px] font-medium transition-colors cursor-pointer"
                    >
                      Delete
                    </button>
                    <button
                      onClick={() => setConfirmDeleteGroupId(null)}
                      className="px-2 py-0.5 rounded bg-secondary hover:bg-accent text-foreground text-[11px] font-medium transition-colors cursor-pointer"
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <>
                <button
                  onClick={() => setEditing({ kind: 'new-preset', groupId: group.id })}
                  className={iconButton}
                  title="Add a filter to this group"
                >
                  <TbPlus className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => {
                    setRenamingGroupId(group.id);
                    setRenameDraft(group.name);
                  }}
                  className={iconButton}
                  title="Rename group"
                >
                  <TbPencil className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => handleDeleteGroup(group.id, group.presets.length)}
                  className={`${iconButton} hover:text-rose-500`}
                  title="Delete group"
                >
                  <TbTrash className="w-3.5 h-3.5" />
                </button>
                  </>
                )}
              </div>

              {!isCollapsed && (
                <div
                  className="p-1.5 flex flex-col gap-1"
                  // An empty group still has to accept a drop, and it has no
                  // rows to compute an index from - index 0 is the only slot.
                  onDragOver={(e) => {
                    if (dragRef.current?.kind !== 'preset' || group.presets.length > 0) return;
                    e.preventDefault();
                    setPresetDrop({ groupId: group.id, index: 0 });
                  }}
                >
                  {group.presets.length === 0 && editing?.kind !== 'new-preset' && (
                    <div
                      className={`text-[11px] italic text-muted-foreground px-2 py-2 rounded border border-dashed transition-colors ${
                        presetDrop?.groupId === group.id ? 'border-primary text-primary' : 'border-border'
                      }`}
                    >
                      Empty group - drag a filter here, or use +
                    </div>
                  )}

                  {group.presets.map((preset, presetIndex) => {
                    if (editing?.kind === 'edit-preset' && editing.presetId === preset.id) {
                      return (
                        <FilterPresetEditor
                          key={preset.id}
                          initialName={preset.name}
                          initialFilter={preset.filter}
                          initialDescription={preset.description}
                          submitLabel="Save"
                          onSubmit={(values) => {
                            onChange(updatePreset(library, preset.id, values));
                            setEditing(null);
                          }}
                          onCancel={() => setEditing(null)}
                        />
                      );
                    }

                    const isDraggingThis = drag?.kind === 'preset' && drag.presetId === preset.id;
                    const showBefore =
                      presetDrop?.groupId === group.id && presetDrop.index === presetIndex;
                    const showAfter =
                      presetDrop?.groupId === group.id && presetDrop.index === presetIndex + 1;

                    return (
                      <div
                        key={preset.id}
                        onDragOver={(e) => handlePresetRowDragOver(e, group.id, presetIndex)}
                        className={`group/row flex items-center gap-1 px-1 py-1 rounded transition-colors hover:bg-accent/50 ${
                          isDraggingThis ? 'opacity-40' : ''
                        } ${showBefore ? 'border-t-2 border-t-primary' : ''} ${
                          showAfter ? 'border-b-2 border-b-primary' : ''
                        }`}
                      >
                        <span
                          draggable
                          onDragStart={() => setDrag({ kind: 'preset', presetId: preset.id })}
                          title="Drag to reorder or move to another group"
                          className="p-0.5 text-muted-foreground hover:text-foreground cursor-grab active:cursor-grabbing shrink-0"
                        >
                          <TbGripVertical className="w-3.5 h-3.5" />
                        </span>

                        <div className="flex-1 min-w-0">
                          <div className="text-xs text-foreground truncate">{preset.name}</div>
                          {preset.filter ? (
                            <code className="block text-[10px] text-primary font-mono truncate">
                              {preset.filter}
                            </code>
                          ) : (
                            <span className="text-[10px] text-muted-foreground italic">
                              No filter (show all)
                            </span>
                          )}
                        </div>

                        {/* Revealed on hover: at rest the list should read as
                            filters, not as rows of buttons. */}
                        <div className="flex items-center opacity-0 group-hover/row:opacity-100 focus-within:opacity-100 transition-opacity shrink-0">
                          <button
                            onClick={() => setEditing({ kind: 'edit-preset', presetId: preset.id })}
                            className={iconButton}
                            title="Edit filter"
                          >
                            <TbPencil className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => onChange(deletePreset(library, preset.id))}
                            className={`${iconButton} hover:text-rose-500`}
                            title="Delete filter"
                          >
                            <TbTrash className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    );
                  })}

                  {editing?.kind === 'new-preset' && editing.groupId === group.id && (
                    <FilterPresetEditor
                      submitLabel="Add filter"
                      onSubmit={(values) => {
                        onChange(addPreset(library, group.id, values));
                        setEditing(null);
                      }}
                      onCancel={() => setEditing(null)}
                    />
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="flex items-center gap-2 border-t border-border pt-3">
        <button
          onClick={handleAddGroup}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-secondary hover:bg-accent text-foreground text-xs font-medium transition-colors cursor-pointer"
        >
          <TbFolderPlus className="w-3.5 h-3.5" />
          New group
        </button>

        <div className="flex-1" />

        {confirmRestore ? (
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-muted-foreground">Replace all filters?</span>
            <button
              onClick={() => {
                onChange(DEFAULT_FILTER_PRESET_LIBRARY);
                setConfirmRestore(false);
              }}
              className="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white text-xs font-medium transition-colors cursor-pointer"
            >
              Restore
            </button>
            <button
              onClick={() => setConfirmRestore(false)}
              className="px-2.5 py-1 rounded bg-secondary hover:bg-accent text-foreground text-xs font-medium transition-colors cursor-pointer"
            >
              Cancel
            </button>
          </div>
        ) : (
          <button
            onClick={() => setConfirmRestore(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent text-xs font-medium transition-colors cursor-pointer"
            title="Discard your changes and restore the filters Inwire ships with"
          >
            <TbRestore className="w-3.5 h-3.5" />
            Restore defaults
          </button>
        )}
      </div>
    </div>
  );
};
