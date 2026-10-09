// Listed for removal (plan step 15): renamed to flow-assets.ts with the
// `/flow-assets/` endpoint (plan 11.1). Thin re-export kept so old imports
// compile; new code imports from './flow-assets'.
export {
  type FlowAsset,
  type FlowAsset as DataFlowAsset,
  flowAssetKeys,
  useFlowAssets,
  useFlowAssets as useDataFlowAssets,
  useCreateFlowAsset,
  useCreateFlowAsset as useCreateDataFlowAsset,
  useUpdateFlowAsset,
  useUpdateFlowAsset as useUpdateDataFlowAsset,
  useDeleteFlowAsset,
  useDeleteFlowAsset as useDeleteDataFlowAsset,
} from './flow-assets'
