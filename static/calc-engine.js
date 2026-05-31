/* UK Benefits Calculator — client-side calculation engine */
(function (global) {
  'use strict';

  var PALETTE = ['var(--c-uc)', 'var(--c-child)', 'var(--c-housing)', 'var(--c-other)'];

  function roundMoney(n) {
    return Math.round((n + 1e-9) * 100) / 100;
  }

  function currency(n) {
    var abs = Math.abs(n);
    var fmt = abs.toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    return (n < 0 ? '-' : '') + '£' + fmt;
  }

  function ucStandardAllowance(ageBand, household) {
    if (household === 'couple') return ageBand === '25_plus' ? 666.97 : 528.34;
    return ageBand === '25_plus' ? 424.90 : 338.58;
  }

  function ucHealthElement(health) {
    if (health === 'severe') return 429.80;
    if (health === 'standard') return 217.26;
    return 0;
  }

  function childBenefitWeekly(children) {
    children = Math.max(0, Math.floor(children));
    if (children <= 0) return 0;
    return 27.05 + Math.max(0, children - 1) * 17.90;
  }

  function weeklyToMonthly(w) { return w * 52 / 12; }
  function annualToMonthly(a) { return a / 12; }

  function buildVisual(estimate) {
    var breakdown = estimate.breakdown || [];
    var positiveRows = [];
    for (var i = 0; i < breakdown.length; i++) {
      var label = breakdown[i][0], value = breakdown[i][1];
      if (label.toLowerCase().indexOf('percentage') !== -1) continue;
      if (typeof value === 'number' && value > 0) positiveRows.push([label, value]);
    }
    if (!positiveRows.length) {
      var amt = Math.max(estimate.primary_amount || 0, 0);
      positiveRows = [[estimate.primary_label || 'Estimated amount', amt || 1]];
    }
    var total = positiveRows.reduce(function (s, r) { return s + r[1]; }, 0) || 1;
    var topRows = positiveRows.slice(0, 3);
    if (positiveRows.length > 3) {
      var otherTotal = positiveRows.slice(3).reduce(function (s, r) { return s + r[1]; }, 0);
      topRows.push(['Other included support', otherTotal]);
    }
    var legend = [], segments = [], current = 0;
    for (var j = 0; j < topRows.length; j++) {
      var lbl = topRows[j][0], val = topRows[j][1];
      var share = Math.max(3, Math.round((val / total) * 1000) / 10);
      var color = PALETTE[j % PALETTE.length];
      legend.push({ label: lbl, value: roundMoney(val), share: share, color: color });
      var next = Math.min(100, current + share);
      segments.push(color + ' ' + current.toFixed(1) + '% ' + next.toFixed(1) + '%');
      current = next;
    }
    if (current < 100) segments.push('var(--surface-alt) ' + current.toFixed(1) + '% 100%');
    return { legend: legend, conic: segments.join(', '), explainer: 'Visual split of the main amounts included in this estimate.' };
  }

  /* ---- individual calculators ---- */

  function universalCredit(inp) {
    var savings = inp.savings || 0;
    if (savings >= 16000) {
      return {
        primary_amount: 0, secondary_amount: 0,
        primary_label: 'Estimated monthly Universal Credit',
        secondary_label: 'Estimated annual Universal Credit',
        summary: 'Savings of £16,000 or more usually stop a standard Universal Credit award.',
        breakdown: [['Standard allowance',0],['Children',0],['Housing support',0],['Childcare support',0],['Health element',0],['Earnings deduction',0],['Savings deduction',0]],
        notes: ['This estimator uses current monthly standard allowances and simplified housing assumptions.','Some households can still receive transitional protection or specialist elements not modelled here.'],
      };
    }
    var base = ucStandardAllowance(inp.age_band, inp.household);
    var children = Math.max(0, Math.floor(inp.children || 0));
    var childElement = children * 303.94;
    if (children > 0 && inp.first_child_pre_2017) childElement += 47.94;
    var housingSupport = Math.min(inp.housing_cost || 0, 1200);
    var childcareCap = children >= 2 ? 1836.16 : 1071.09;
    var childcareSupport = Math.min((inp.childcare_cost || 0) * 0.85, childcareCap);
    var health = ucHealthElement(inp.health);
    var workAllowance = housingSupport > 0 ? 404 : 673;
    var earningsDeduction = Math.max(0, (inp.earnings || 0) - workAllowance) * 0.55;
    var savingsDeduction = 0;
    if (savings > 6000) savingsDeduction = Math.ceil((savings - 6000) / 250) * 4.35;
    var monthly = Math.max(0, base + childElement + housingSupport + childcareSupport + health - earningsDeduction - savingsDeduction);
    return {
      primary_amount: roundMoney(monthly), secondary_amount: roundMoney(monthly * 12),
      primary_label: 'Estimated monthly Universal Credit',
      secondary_label: 'Estimated annual Universal Credit',
      summary: 'A simplified award estimate using the 55% earnings taper, a work allowance where children or a health condition apply, savings deductions over £6,000, and capped childcare support.',
      breakdown: [['Standard allowance', base],['Child element', childElement],['Housing support used', housingSupport],['Childcare support used', childcareSupport],['Health element', health],['Earnings deduction', -earningsDeduction],['Savings deduction', -savingsDeduction]],
      notes: ['Universal Credit now pays the child element for every eligible child after the 6 April 2026 rule change.','Housing support is simplified here. Actual help depends on your rent type, service charges and local housing allowance rules.'],
    };
  }

  function childBenefit(inp) {
    var weekly = childBenefitWeekly(inp.children || 0);
    var monthly = weeklyToMonthly(weekly);
    var annual = weekly * 52;
    var ch = Math.max(0, Math.floor(inp.children || 0));
    return {
      primary_amount: roundMoney(weekly), secondary_amount: roundMoney(annual),
      primary_label: 'Estimated weekly Child Benefit',
      secondary_label: 'Estimated annual Child Benefit',
      summary: 'This uses the published 2026 to 2027 Child Benefit rates for the eldest child and any additional children.',
      breakdown: [['Eldest or only child', ch >= 1 ? 27.05 : 0],['Additional children', Math.max(0, ch - 1) * 17.90],['Monthly equivalent', monthly]],
      notes: ['If anyone in the household has adjusted net income over £60,000, check the HICBC page next.','You can claim Child Benefit and opt out of payments if you want National Insurance credits without the cash payment.'],
    };
  }

  function hicbc(inp) {
    var annual = childBenefitWeekly(inp.children || 0) * 52;
    var income = inp.adjusted_net_income || 0;
    var charge = 0;
    if (income > 60000) {
      charge = income >= 80000 ? annual : annual * Math.min(1, (income - 60000) / 20000);
    }
    var keep = Math.max(0, annual - charge);
    return {
      primary_amount: roundMoney(charge), secondary_amount: roundMoney(keep),
      primary_label: 'Estimated annual HICBC charge',
      secondary_label: 'Estimated Child Benefit kept',
      summary: 'The charge starts above £60,000 adjusted net income and reaches 100% when income is £80,000 or more.',
      breakdown: [['Annual Child Benefit used', annual],['Adjusted net income', income],['Estimated charge', -charge],['Net amount retained', keep]],
      notes: ['This uses the post-April 2024 HICBC taper of 1% for each £200 over £60,000.','Adjusted net income can be reduced by certain pension contributions and Gift Aid, so the real charge can differ.'],
    };
  }

  function pensionCredit(inp) {
    var base = inp.household === 'couple' ? 363.25 : 238.0;
    var severe = inp.severe_disability ? 86.05 : 0;
    var carer = inp.carer ? 48.15 : 0;
    var savingsIncome = 0;
    var sav = inp.savings || 0;
    if (sav > 10000) {
      var excess = sav - 10000;
      savingsIncome = Math.floor(excess / 500) + (excess % 500 ? 1 : 0);
    }
    var weekly = Math.max(0, base + severe + carer - (inp.weekly_income || 0) - savingsIncome);
    return {
      primary_amount: roundMoney(weekly), secondary_amount: roundMoney(weekly * 52),
      primary_label: 'Estimated weekly Pension Credit',
      secondary_label: 'Estimated annual Pension Credit',
      summary: 'This focuses on Guarantee Credit and uses the standard weekly minimum income levels plus optional severe disability and carer additions.',
      breakdown: [['Guarantee Credit minimum', base],['Severe disability addition', severe],['Carer addition', carer],['Income counted', -(inp.weekly_income || 0)],['Savings treated as income', -savingsIncome]],
      notes: ['Savings under £10,000 are ignored. Above that, every £500 generally counts as £1 a week of income.','Housing costs, Savings Credit and mixed-age couple rules are not fully modelled here.'],
    };
  }

  function pip(inp) {
    var daily = inp.daily_living_points || 0;
    var mob = inp.mobility_points || 0;
    var dailyRate = daily >= 12 ? 114.60 : daily >= 8 ? 76.70 : 0;
    var mobRate = mob >= 12 ? 80.00 : mob >= 8 ? 30.30 : 0;
    var dailyBand = daily >= 12 ? 'Enhanced daily living indicated' : daily >= 8 ? 'Standard daily living indicated' : 'No daily living award indicated';
    var mobBand = mob >= 12 ? 'Enhanced mobility indicated' : mob >= 8 ? 'Standard mobility indicated' : 'No mobility award indicated';
    var total = dailyRate + mobRate;
    return {
      primary_amount: roundMoney(total), secondary_amount: roundMoney(total * 52),
      primary_label: 'Indicative weekly PIP amount',
      secondary_label: 'Indicative annual PIP amount',
      summary: dailyBand + '. ' + mobBand + '. PIP is based on descriptors and evidence, not income.',
      breakdown: [['Daily living component', dailyRate],['Mobility component', mobRate],['Combined weekly amount', total]],
      notes: ['This is a points-based checker, not an official DWP decision tool.','Real awards depend on the evidence you provide, how long your condition affects you and a formal assessment process.'],
    };
  }

  function councilTaxReduction(inp) {
    var ct = inp.monthly_council_tax || 0;
    var income = inp.monthly_income || 0;
    var reduction = 0;
    if (inp.on_means_tested_benefit) {
      reduction = 1;
    } else if (income <= 1100) {
      reduction = 0.85;
    } else if (income <= 1600) {
      reduction = 0.60;
    } else if (income <= 2200) {
      reduction = 0.35;
    }
    if (inp.single_adult) reduction = Math.max(reduction, 0.25);
    if ((inp.savings || 0) > 16000 && !inp.on_guarantee_pension_credit) reduction = 0;
    var help = ct * Math.min(reduction, 1);
    return {
      primary_amount: roundMoney(help), secondary_amount: roundMoney(help * 12),
      primary_label: 'Estimated monthly council tax help',
      secondary_label: 'Estimated annual council tax help',
      summary: 'Council Tax Reduction is set locally, so this page uses broad low-income bands and flags where means-tested benefits or a single-person discount usually strengthen entitlement.',
      breakdown: [['Current monthly council tax', ct],['Reduction percentage used', roundMoney(Math.min(reduction, 1) * 100)],['Estimated monthly help', help]],
      notes: ['Each council runs its own scheme. Treat this as a directional estimate only.','If you already qualify for the 25% single person discount, your remaining bill may still be reduced further by CTR depending on the local rules.'],
    };
  }

  function housingBenefit(inp) {
    var rent = inp.weekly_rent || 0;
    var income = inp.weekly_income || 0;
    var reduction = 0;
    if (inp.legacy_claimant) {
      if (income <= 120) reduction = 1;
      else if (income <= 200) reduction = 0.75;
      else if (income <= 300) reduction = 0.45;
      else reduction = 0.2;
      if (inp.spare_room) reduction -= 0.14;
    }
    if ((inp.savings || 0) >= 16000 && !inp.pension_age) reduction = 0;
    var weekly = Math.max(0, rent * Math.max(0, reduction));
    return {
      primary_amount: roundMoney(weekly), secondary_amount: roundMoney(weekly * 52),
      primary_label: 'Estimated weekly Housing Benefit',
      secondary_label: 'Estimated annual Housing Benefit',
      summary: 'Housing Benefit is now mainly for pension-age households and some supported or temporary housing cases, so this estimator is designed as a legacy checker rather than a new-claim tool.',
      breakdown: [['Weekly eligible rent used', rent],['Income band applied', income],['Estimated weekly support', weekly]],
      notes: ['Most new working-age claims now go through Universal Credit housing costs instead of Housing Benefit.','Bedroom tax, local housing allowance, non-dependant deductions and service charge rules are simplified here.'],
    };
  }

  function benefitCap(inp) {
    var inside = inp.inside_london;
    var hh = inp.household;
    var cap = inside
      ? (hh === 'couple' || hh === 'single_parent' ? 2110.25 : 1413.92)
      : (hh === 'couple' || hh === 'single_parent' ? 1835.00 : 1229.42);
    var benefits = inp.monthly_benefits || 0;
    var excess = Math.max(0, benefits - cap);
    return {
      primary_amount: roundMoney(excess), secondary_amount: roundMoney(Math.max(0, benefits - excess)),
      primary_label: 'Estimated monthly amount over the cap',
      secondary_label: 'Estimated capped benefit total',
      summary: 'The benefit cap depends mainly on whether you live inside Greater London and whether you are a couple, single parent or single adult.',
      breakdown: [['Monthly benefit total entered', benefits],['Monthly cap used', cap],['Amount over cap', -excess]],
      notes: ['Some households are exempt from the cap, including many people receiving disability-related benefits.','If you are on Universal Credit, earnings can also stop the cap applying in some cases.'],
    };
  }

  function ssp(inp) {
    var awe = inp.average_weekly_earnings || 0;
    var weekly = Math.min(123.25, awe * 0.8);
    var weeks = Math.min(28, inp.weeks_off || 0);
    var total = weekly * weeks;
    return {
      primary_amount: roundMoney(weekly), secondary_amount: roundMoney(total),
      primary_label: 'Estimated weekly SSP',
      secondary_label: 'Estimated total SSP for absence',
      summary: 'This follows the April 2026 SSP structure: the lower of £123.25 a week or 80% of average weekly earnings, for up to 28 weeks.',
      breakdown: [['Average weekly earnings', awe],['Weekly SSP used', weekly],['Weeks used', weeks]],
      notes: ['From 6 April 2026, SSP is generally payable from the first full day of sickness absence for eligible employees.','Your employer may pay more under a contractual sick pay scheme.'],
    };
  }

  function maternityComparison(inp) {
    var awe = inp.average_weekly_earnings || 0;
    var smpTotal = 0, maTotal = 0;
    if (inp.employed_long_enough) smpTotal = Math.min(awe * 0.9, awe) * 6 + Math.min(187.18, awe * 0.9) * 33;
    if (inp.employed_or_self_employed_long_enough) maTotal = Math.min(194.32, awe * 0.9) * 39;
    var better = smpTotal >= maTotal ? 'Statutory Maternity Pay' : 'Maternity Allowance';
    return {
      primary_amount: roundMoney(smpTotal), secondary_amount: roundMoney(maTotal),
      primary_label: 'Estimated total Statutory Maternity Pay',
      secondary_label: 'Estimated total Maternity Allowance',
      summary: 'Based on the eligibility boxes you selected, ' + better + ' looks stronger on headline amount.',
      breakdown: [['SMP total', smpTotal],['Maternity Allowance total', maTotal]],
      notes: ['SMP usually requires 26 weeks with the same employer into the qualifying week. Maternity Allowance can help where SMP is not available.','Both estimates assume the full 39 weeks of payable maternity support.'],
    };
  }

  function esa(inp) {
    var weekly = 0;
    if (inp.has_recent_ni_record) {
      weekly = inp.group === 'support' ? 145.90 : 95.55;
      var pension = inp.private_pension_weekly || 0;
      if (pension > 85) weekly -= (pension - 85) / 2;
    }
    weekly = Math.max(0, weekly);
    var base = inp.has_recent_ni_record ? (inp.group === 'support' ? 145.90 : 95.55) : 0;
    return {
      primary_amount: roundMoney(weekly), secondary_amount: roundMoney(weekly * 52),
      primary_label: 'Indicative weekly New Style ESA',
      secondary_label: 'Indicative annual New Style ESA',
      summary: 'This page estimates New Style ESA using the work-related activity and support group weekly rates, then adjusts for private pension income above £85 a week.',
      breakdown: [['Base weekly ESA used', base],['Private pension entered', inp.private_pension_weekly || 0],['Indicative ESA after pension adjustment', weekly]],
      notes: ['You cannot usually get New Style ESA at the same time as Statutory Sick Pay.','Many households can claim Universal Credit alongside or instead of ESA, but UC may then be reduced by the ESA amount.'],
    };
  }

  function jsa(inp) {
    var weekly = 0;
    if (inp.has_recent_ni_record && (inp.hours_worked || 0) < 16) {
      weekly = inp.age_band === '25_plus' ? 95.55 : 75.65;
    }
    return {
      primary_amount: roundMoney(weekly), secondary_amount: roundMoney(Math.min(182 / 7 * weekly, weekly * 26)),
      primary_label: 'Indicative weekly New Style JSA',
      secondary_label: 'Indicative six-month JSA total',
      summary: 'New Style JSA depends heavily on National Insurance history, age and whether you are working fewer than 16 hours a week.',
      breakdown: [['Weekly JSA used', weekly],['Hours worked each week', inp.hours_worked || 0]],
      notes: ['New claims are for New Style JSA. Income-based JSA is a legacy benefit.','If your NI record is weak or your income is low, Universal Credit may be the more relevant route to check.'],
    };
  }

  function workingTaxCredit(inp) {
    var max = 2435;
    if (inp.household === 'couple' || inp.household === 'lone_parent') max += 2500;
    if ((inp.hours_worked || 0) >= 30) max += 1015;
    if (inp.disabled_worker) max += 3935;
    var withdrawal = Math.max(0, (inp.annual_income || 0) - 7955) * 0.41;
    var annual = Math.max(0, max - withdrawal);
    return {
      primary_amount: roundMoney(annual), secondary_amount: roundMoney(annualToMonthly(annual)),
      primary_label: 'Indicative annual Working Tax Credit',
      secondary_label: 'Indicative monthly equivalent',
      summary: 'Working Tax Credit ended for new claims on 5 April 2025. This page is a legacy reference estimator using the last published 2024 to 2025 rates.',
      breakdown: [['Maximum award basis used', max],['Income reduction applied', -withdrawal],['Legacy annual estimate', annual]],
      notes: ['This is mainly useful for transitional protection conversations, disputes and historic award checking.','Most new low-income support claims now go through Universal Credit instead of tax credits.'],
    };
  }

  function childTaxCredit(inp) {
    var children = Math.max(0, Math.floor(inp.children || 0));
    var max = 545 + children * 3455;
    var threshold = inp.ctc_only ? 19995 : 7955;
    var withdrawal = Math.max(0, (inp.annual_income || 0) - threshold) * 0.41;
    var annual = Math.max(0, max - withdrawal);
    return {
      primary_amount: roundMoney(annual), secondary_amount: roundMoney(annualToMonthly(annual)),
      primary_label: 'Indicative annual Child Tax Credit',
      secondary_label: 'Indicative monthly equivalent',
      summary: 'Child Tax Credit also closed to new claims on 5 April 2025. This page uses the final published legacy rates as a reference estimate.',
      breakdown: [['Family and child elements', max],['Income reduction applied', -withdrawal],['Legacy annual estimate', annual]],
      notes: ['Use this for historic or transitional cases only. New support for children is generally through Universal Credit and Child Benefit.','Disability additions are not fully modelled on this simplified page.'],
    };
  }

  function taxFreeChildcare(inp) {
    var children = Math.max(1, Math.floor(inp.children || 1));
    var cap = (inp.disabled_child ? 1000 : 500) * 4 * children;
    var spend = Math.max(0, inp.annual_childcare_cost || 0);
    var topUp = Math.min(spend * 0.25, cap);
    return {
      primary_amount: roundMoney(topUp), secondary_amount: roundMoney(topUp / 12),
      primary_label: 'Estimated annual Tax-Free Childcare top-up',
      secondary_label: 'Estimated monthly equivalent',
      summary: 'Tax-Free Childcare adds £2 for every £8 you pay in, up to the published quarterly caps for each child.',
      breakdown: [['Annual childcare cost entered', spend],['Government top-up used', topUp]],
      notes: ['You cannot get Tax-Free Childcare at the same time as Universal Credit childcare support.','The scheme normally stops the September after your child turns 11, or 16 if they are disabled.'],
    };
  }

  function sureStart(inp) {
    var eligible = inp.qualifying_benefit && (inp.first_child || inp.multiple_birth_with_other_children);
    var amount = eligible ? 500 : 0;
    return {
      primary_amount: amount, secondary_amount: amount,
      primary_label: 'Indicative Sure Start Maternity Grant',
      secondary_label: 'One-off payment if eligible',
      summary: 'Sure Start Maternity Grant is a one-off £500 payment for eligible households, usually linked to a first child or some multiple birth cases.',
      breakdown: [['One-off grant', amount]],
      notes: ['The claim window is usually from 11 weeks before the due date until 6 months after birth.','Scotland uses different family payment schemes instead of Sure Start Maternity Grant.'],
    };
  }

  function healthyStart(inp) {
    var eligible = inp.pregnant_or_child_under_4 && (inp.qualifying_benefit || inp.under_18_and_pregnant);
    var monthly = eligible ? 17 : 0;
    return {
      primary_amount: monthly, secondary_amount: roundMoney(monthly * 12),
      primary_label: 'Indicative monthly Healthy Start value',
      secondary_label: 'Indicative annual value',
      summary: 'This checker focuses on whether you are in the right pregnancy or child age group and whether a qualifying benefit route is in place.',
      breakdown: [['Indicative monthly support', monthly]],
      notes: ['Healthy Start support is delivered through a prepaid card and free vitamins rather than a standard benefit payment.','The exact value varies by household composition and nation-specific alternatives apply in Scotland.'],
    };
  }

  function freeSchoolMeals(inp) {
    var ucRoute = inp.on_universal_credit && (inp.annual_take_home_income || 0) < 7400;
    var eligible = ucRoute || inp.other_qualifying_benefit || inp.infant_pupil;
    var meals = eligible ? 190 * Math.max(0, Math.floor(inp.children || 0)) : 0;
    return {
      primary_amount: meals, secondary_amount: meals,
      primary_label: 'Indicative school-year value of free meals',
      secondary_label: 'Indicative annual family value',
      summary: 'Eligibility in England depends mainly on qualifying benefits, with a specific £7,400 post-tax earnings test for most Universal Credit cases and universal infant free meals for reception to year 2.',
      breakdown: [['Children included', inp.children || 0],['School-year value used', meals]],
      notes: ['This page is aimed at England. Scotland, Wales and Northern Ireland use different rules.','The cash value shown is illustrative. Your actual gain depends on school term dates and meal pricing locally.'],
    };
  }

  function winterFuel(inp) {
    var eligible = inp.born_before_cutoff && inp.lives_in_england_or_wales;
    var amount = 0;
    if (eligible) {
      amount = inp.born_before_older_cutoff ? 300 : 200;
      if (inp.income_over_35000) amount = 0;
    }
    return {
      primary_amount: amount, secondary_amount: amount,
      primary_label: 'Indicative Winter Fuel Payment',
      secondary_label: 'One-off winter payment',
      summary: 'This follows the 2026 to 2027 qualifying week age tests and flags the current £35,000 personal income clawback.',
      breakdown: [['Indicative payment', amount]],
      notes: ['Most eligible households are paid automatically in November or December.','Scotland uses Pension Age Winter Heating Payment instead, and Northern Ireland has separate arrangements.'],
    };
  }

  function coldWeather(inp) {
    var eligible = inp.qualifying_benefit && inp.lives_outside_scotland;
    var total = eligible ? 25 * Math.max(0, Math.floor(inp.triggered_periods || 0)) : 0;
    return {
      primary_amount: total, secondary_amount: total,
      primary_label: 'Estimated Cold Weather Payment total',
      secondary_label: 'Winter total based on triggered periods',
      summary: 'Cold Weather Payments are £25 for each 7-day cold spell trigger in your area between 1 November and 31 March.',
      breakdown: [['Triggered cold spells entered', inp.triggered_periods || 0],['Estimated total', total]],
      notes: ['The payment is automatic when your postcode area triggers and you meet the qualifying benefit rules.','Scotland uses Winter Heating Payment instead of Cold Weather Payments.'],
    };
  }

  function savingsImpact(inp) {
    var savings = inp.savings || 0;
    var threshold = 6000;
    var excess = Math.max(0, savings - threshold);
    var bands = excess > 0 ? Math.ceil(excess / 250) : 0;
    var monthly = bands * 4.35;
    if (savings >= 16000) {
      return {
        primary_amount: 0, secondary_amount: 0,
        primary_label: 'Monthly UC deduction from savings',
        secondary_label: 'Annual UC reduction',
        summary: 'Savings of £16,000 or more mean you are not normally eligible for Universal Credit at all.',
        breakdown: [['Savings threshold', threshold],['Savings entered', savings],['UC award', 0]],
        notes: ['At £16,000 or more in savings, Universal Credit is not normally payable.','Savings below £6,000 have no effect on your Universal Credit award.'],
      };
    }
    return {
      primary_amount: roundMoney(monthly), secondary_amount: roundMoney(monthly * 12),
      primary_label: 'Monthly UC deduction from savings',
      secondary_label: 'Annual UC reduction from savings',
      summary: 'Savings of ' + currency(savings) + ' generate an assumed monthly income of ' + currency(monthly) + ', which reduces your Universal Credit by that amount.',
      breakdown: [['Lower threshold', threshold],['Excess savings above £6,000', excess],['£250 bands above threshold', bands],['Tariff income rate per band', 4.35],['Monthly UC deduction', monthly]],
      notes: ['For every complete £250 above £6,000, DWP adds £4.35 to assumed monthly income, reducing Universal Credit by the same amount.','Savings below £6,000 are fully disregarded. At £16,000 or more, UC eligibility normally stops entirely.'],
    };
  }

  function earningsImpact(inp) {
    var earnings = inp.earnings || 0;
    var children = Math.max(0, Math.floor(inp.children || 0));
    var housingCost = inp.housing_cost || 0;
    var hasWorkAllowance = children > 0;
    var workAllowance = hasWorkAllowance ? (housingCost > 0 ? 404 : 673) : 0;
    var taxable = Math.max(0, earnings - workAllowance);
    var reduction = roundMoney(taxable * 0.55);
    var extra = earnings >= workAllowance ? roundMoney(100 * 0.55) : roundMoney(Math.max(0, earnings + 100 - workAllowance) * 0.55);
    var kept = roundMoney(100 - extra);
    return {
      primary_amount: reduction, secondary_amount: kept,
      primary_label: 'Monthly UC reduction at current earnings',
      secondary_label: 'UC kept per extra £100 earned',
      summary: 'After the ' + currency(workAllowance) + ' work allowance, the 55% taper reduces UC by ' + currency(reduction) + ' a month. For each extra £100 earned, you keep ' + currency(kept) + ' net.',
      breakdown: [['Monthly earnings entered', earnings],['Work allowance', workAllowance],['Earnings above work allowance', Math.max(0, taxable)],['55% taper deduction', -reduction],['UC kept per £100 extra earned', kept]],
      notes: ['The work allowance (£404 or £673 depending on housing support) only applies if you have children or a health/disability element.','Without a work allowance the 55% taper starts from the first pound of net earnings.'],
    };
  }

  function maternityPay(inp) {
    var wp = inp.weekly_pay || 0;
    var wh = Math.min(Math.floor(inp.weeks_higher || 0), 6);
    var wl = Math.min(Math.floor(inp.weeks_lower || 0), 33);
    var lower = 184.03;
    var higherTotal = wp * 0.9 * wh;
    var lowerTotal = lower * wl;
    var total = higherTotal + lowerTotal;
    return {
      primary_amount: roundMoney(total), secondary_amount: roundMoney(wp * 0.9),
      primary_label: 'Estimated total SMP over maternity leave',
      secondary_label: 'Weekly SMP in the first 6 weeks (90%)',
      summary: 'Statutory Maternity Pay estimated at ' + currency(wp * 0.9) + '/week for the first ' + wh + ' weeks, then ' + currency(lower) + '/week for ' + wl + ' weeks.',
      breakdown: [['Average weekly pay entered', wp],['First 6 weeks — 90% of pay', roundMoney(wp * 0.9)],['Weeks at higher rate (' + wh + ')', higherTotal],['Flat rate weeks — £' + lower + '/week', lower],['Weeks at flat rate (' + wl + ')', lowerTotal],['Estimated total SMP', total]],
      notes: ['SMP is normally payable for up to 39 weeks. The first 6 weeks are paid at 90% of average weekly earnings; weeks 7 to 39 are paid at the statutory flat rate (£184.03 in 2026/27) or 90% of earnings if lower.','You need to have been employed for at least 26 weeks into the qualifying week and earning above the lower earnings limit to qualify.'],
    };
  }

  function taxFreeChildcareMonthly(inp) {
    var monthly = inp.monthly_childcare || 0;
    var children = Math.max(1, Math.floor(inp.children || 1));
    var annualSpend = monthly * 12;
    var cap = 2000 * children;
    var topUp = Math.min(annualSpend * 0.25, cap);
    var monthlyTopUp = topUp / 12;
    return {
      primary_amount: roundMoney(monthlyTopUp), secondary_amount: roundMoney(topUp),
      primary_label: 'Estimated monthly government top-up',
      secondary_label: 'Estimated annual government top-up',
      summary: 'For ' + currency(monthly) + '/month on childcare, the government adds ' + currency(monthlyTopUp) + '/month — up to the annual cap of ' + currency(cap) + ' for ' + children + ' child' + (children > 1 ? 'ren' : '') + '.',
      breakdown: [['Monthly childcare entered', monthly],['Annual childcare spend', annualSpend],['Annual cap used', cap],['Government top-up (20p per 80p)', topUp],['Monthly equivalent', monthlyTopUp]],
      notes: ['The government adds 20p for every 80p you pay in, up to £500 per child per quarter (£2,000 per year) for most children.','You cannot use Tax-Free Childcare at the same time as Universal Credit childcare support — compare both before choosing.'],
    };
  }

  function attendanceAllowance(inp) {
    var isHigher = inp.rate === 'higher';
    var weekly = isHigher ? 110.40 : 73.90;
    var annual = roundMoney(weekly * 52);
    var label = isHigher ? 'higher rate' : 'lower rate';
    return {
      primary_amount: roundMoney(weekly), secondary_amount: annual,
      primary_label: 'Estimated weekly Attendance Allowance',
      secondary_label: 'Estimated annual Attendance Allowance',
      summary: 'The ' + label + ' of Attendance Allowance is ' + currency(weekly) + ' a week in 2026/27 (' + currency(annual) + ' a year). It is not means tested — income and savings have no effect.',
      breakdown: [['Weekly Attendance Allowance', weekly],['Annual equivalent (52 weeks)', annual]],
      notes: ['Attendance Allowance is non-means-tested — income, savings and whether you live with a partner have no effect.','Lower rate: care needs during the day or night. Higher rate: care needs day and night, or terminally ill.','Receiving Attendance Allowance can passport you to higher Pension Credit, Council Tax Reduction and Housing Benefit awards.','Attendance Allowance is for people over State Pension age. Under State Pension age, PIP applies instead.'],
    };
  }

  function carersAllowance(inp) {
    var earnings = inp.weekly_earnings || 0;
    var hours = inp.hours_caring || 0;
    var hasQB = inp.has_qualifying_benefit;
    var rate = 81.90;
    var limit = 151;
    var weekly, reason;
    if (hours < 35) {
      weekly = 0;
      reason = 'You need to care for at least 35 hours a week. You entered ' + hours + ' hours.';
    } else if (!hasQB) {
      weekly = 0;
      reason = 'The person you care for must receive a qualifying disability benefit (PIP daily living, DLA care, Attendance Allowance or similar).';
    } else if (earnings > limit) {
      weekly = 0;
      reason = 'Your weekly earnings (' + currency(earnings) + ') are above the £' + limit + '/week earnings limit after permitted deductions.';
    } else {
      weekly = rate;
      reason = "Carer's Allowance is " + currency(rate) + " a week in 2026/27 (" + currency(roundMoney(rate * 52)) + " a year) if eligible. It is taxable and may reduce Universal Credit by the same amount.";
    }
    var annual = roundMoney(weekly * 52);
    return {
      primary_amount: roundMoney(weekly), secondary_amount: annual,
      primary_label: "Estimated weekly Carer's Allowance",
      secondary_label: "Estimated annual Carer's Allowance",
      summary: reason,
      breakdown: [["Weekly Carer's Allowance rate", rate],['Your weekly earnings', earnings],['Earnings limit', limit],['Hours caring per week', hours],['Estimated weekly award', weekly]],
      notes: ["Carer's Allowance is taxable and counts as income for Universal Credit purposes — UC will usually be reduced by £1 for every £1 of Carer's Allowance received.","You may still have 'underlying entitlement' to Carer's Allowance even if a higher benefit (like State Pension) prevents actual payment — this can still trigger a carer element in UC.","The earnings limit is £151/week net after tax, NI and 50% of pension contributions.","The person you care for must receive PIP (daily living component), DLA (middle or high care), Attendance Allowance, or similar."],
    };
  }

  var ENGINE = {
    'universal_credit': universalCredit,
    'child_benefit': childBenefit,
    'hicbc': hicbc,
    'pension_credit': pensionCredit,
    'pip': pip,
    'council_tax_reduction': councilTaxReduction,
    'housing_benefit': housingBenefit,
    'benefit_cap': benefitCap,
    'ssp': ssp,
    'maternity_comparison': maternityComparison,
    'esa': esa,
    'jsa': jsa,
    'working_tax_credit': workingTaxCredit,
    'child_tax_credit': childTaxCredit,
    'tax_free_childcare': taxFreeChildcare,
    'sure_start': sureStart,
    'healthy_start': healthyStart,
    'free_school_meals': freeSchoolMeals,
    'winter_fuel': winterFuel,
    'cold_weather': coldWeather,
    'savings_impact': savingsImpact,
    'earnings_impact': earningsImpact,
    'maternity_pay': maternityPay,
    'tax_free_childcare_monthly': taxFreeChildcareMonthly,
    'attendance_allowance': attendanceAllowance,
    'carers_allowance': carersAllowance,
  };

  global.CALC_ENGINE = {
    calculate: function (formula, inputs) {
      var fn = ENGINE[formula];
      if (!fn) return null;
      var estimate = fn(inputs);
      estimate.visual = buildVisual(estimate);
      return estimate;
    },
  };

}(window));
