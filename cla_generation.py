from Defenses import *


minimal_defense_sets = [
['PACMem', 'HexType', 'chow2005shredding'], 
['PACMem', 'HexType', 'SafeInit'],
['PACMem', 'EffectiveSan_type', 'chow2005shredding'],
['PACMem', 'EffectiveSan_type', 'SafeInit'],
['EffectiveSan', 'chow2005shredding'],
['EffectiveSan', 'SafeInit'],
['StickyTags', 'HexType', 'chow2005shredding', 'FFMalloc'],
['StickyTags', 'HexType', 'chow2005shredding', 'MarkUs'],
['StickyTags', 'HexType', 'chow2005shredding', 'DangSan'],
['StickyTags', 'HexType', 'chow2005shredding', 'CETS'],
['StickyTags', 'HexType', 'SafeInit', 'FFMalloc'],
['StickyTags', 'HexType', 'SafeInit', 'MarkUs'],
['StickyTags', 'HexType', 'SafeInit', 'DangSan'],
['StickyTags', 'HexType', 'SafeInit', 'CETS'],
['StickyTags', 'EffectiveSan_type', 'chow2005shredding', 'FFMalloc'],
['StickyTags', 'EffectiveSan_type', 'chow2005shredding', 'MarkUs'],
['StickyTags', 'EffectiveSan_type', 'chow2005shredding', 'DangSan'],
['StickyTags', 'EffectiveSan_type', 'chow2005shredding', 'CETS'],
['StickyTags', 'EffectiveSan_type', 'SafeInit', 'FFMalloc'],
['StickyTags', 'EffectiveSan_type', 'SafeInit', 'MarkUs'],
['StickyTags', 'EffectiveSan_type', 'SafeInit', 'DangSan'],
['StickyTags', 'EffectiveSan_type', 'SafeInit', 'CETS'],
['LowFat', 'HexType', 'chow2005shredding', 'FFMalloc'],
['LowFat', 'HexType', 'chow2005shredding', 'MarkUs'],
['LowFat', 'HexType', 'chow2005shredding', 'DangSan'],
['LowFat', 'HexType', 'chow2005shredding', 'CETS'],
['LowFat', 'HexType', 'SafeInit', 'FFMalloc'],
['LowFat', 'HexType', 'SafeInit', 'MarkUs'],
['LowFat', 'HexType', 'SafeInit', 'DangSan'],
['LowFat', 'HexType', 'SafeInit', 'CETS'],
['LowFat', 'EffectiveSan_type', 'chow2005shredding', 'FFMalloc'],
['LowFat', 'EffectiveSan_type', 'chow2005shredding', 'MarkUs'],
['LowFat', 'EffectiveSan_type', 'chow2005shredding', 'DangSan'],
['LowFat', 'EffectiveSan_type', 'chow2005shredding', 'CETS'],
['LowFat', 'EffectiveSan_type', 'SafeInit', 'FFMalloc'],
['LowFat', 'EffectiveSan_type', 'SafeInit', 'MarkUs'],
['LowFat', 'EffectiveSan_type', 'SafeInit', 'DangSan'],
['LowFat', 'EffectiveSan_type', 'SafeInit', 'CETS'],
['SoftBound', 'HexType', 'chow2005shredding', 'FFMalloc'],
['SoftBound', 'HexType', 'chow2005shredding', 'MarkUs'],
['SoftBound', 'HexType', 'chow2005shredding', 'DangSan'],
['SoftBound', 'HexType', 'chow2005shredding', 'CETS'],
['SoftBound', 'HexType', 'SafeInit', 'FFMalloc'],
['SoftBound', 'HexType', 'SafeInit', 'MarkUs'],
['SoftBound', 'HexType', 'SafeInit', 'DangSan'],
['SoftBound', 'HexType', 'SafeInit', 'CETS'],
['SoftBound', 'EffectiveSan_type', 'chow2005shredding', 'FFMalloc'],
['SoftBound', 'EffectiveSan_type', 'chow2005shredding', 'MarkUs'],
['SoftBound', 'EffectiveSan_type', 'chow2005shredding', 'DangSan'],
['SoftBound', 'EffectiveSan_type', 'chow2005shredding', 'CETS'],
['SoftBound', 'EffectiveSan_type', 'SafeInit', 'FFMalloc'],
['SoftBound', 'EffectiveSan_type', 'SafeInit', 'MarkUs'],
['SoftBound', 'EffectiveSan_type', 'SafeInit', 'DangSan'],
['SoftBound', 'EffectiveSan_type', 'SafeInit', 'CETS'],
['CCured'],
]

graph = ExploitGraph()

set1 = ['Rust']

for defense in minimal_defense_sets:
    print(f'checking interop of {set1} and {defense}')
    for result in run_interop_test(set1, defense, print_results=False):
        if new_goals := result.was_bypassed():
            print(f"\t{result.defense} got interop-bypassed!")
            if completely_new_goals := result.unlocked_completely_new_goals():
                print(f"\t\tit now even allows completely new goals: {completely_new_goals}")
        else:
            print(f"\t{result.defense} not bypassed")

