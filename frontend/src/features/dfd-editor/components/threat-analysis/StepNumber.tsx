/** The step of a column in the "By Use Case" view: 1 use cases, 2 abuse cases, 3 threats, 4 countermeasures. */

export function StepNumber({ step }: { step: number }) {
  return (
    <span
      className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-200 text-[11px] font-semibold text-slate-700"
      aria-label={`Step ${step}`}
    >
      {step}
    </span>
  )
}
