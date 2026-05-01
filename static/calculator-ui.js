(function () {
  'use strict';

  var PAGE = window.CALCULATOR_PAGE || null;
  if (!PAGE) return;

  var FORMULA = PAGE.formula;
  var FIELDS = PAGE.fields || [];
  var form = document.querySelector('.calc-inputs form');
  if (!form || !window.CALC_ENGINE) return;

  var CIRC = 452;
  var SEG_IDS = ['seg-0', 'seg-1', 'seg-2', 'seg-3'];
  var FIELD_QUICK_CHOICES = {
    children: [
      { value: 0, label: 'None' },
      { value: 1, label: '1' },
      { value: 2, label: '2' },
      { value: 3, label: '3' },
      { value: 4, label: '4+' }
    ],
    savings: [
      { value: 0, label: '£0' },
      { value: 6000, label: '£6k' },
      { value: 10000, label: '£10k' },
      { value: 16000, label: '£16k' }
    ],
    earnings: [
      { value: 0, label: '£0' },
      { value: 800, label: '£800' },
      { value: 1200, label: '£1.2k' },
      { value: 1800, label: '£1.8k' }
    ],
    housing_cost: [
      { value: 0, label: '£0' },
      { value: 600, label: '£600' },
      { value: 900, label: '£900' },
      { value: 1200, label: '£1.2k' }
    ],
    childcare_cost: [
      { value: 0, label: '£0' },
      { value: 300, label: '£300' },
      { value: 700, label: '£700' },
      { value: 1200, label: '£1.2k' }
    ],
    adjusted_net_income: [
      { value: 60000, label: '£60k' },
      { value: 70000, label: '£70k' },
      { value: 80000, label: '£80k' }
    ],
    weekly_income: [
      { value: 0, label: '£0' },
      { value: 100, label: '£100' },
      { value: 200, label: '£200' },
      { value: 300, label: '£300' }
    ],
    monthly_income: [
      { value: 800, label: '£800' },
      { value: 1200, label: '£1.2k' },
      { value: 1600, label: '£1.6k' },
      { value: 2200, label: '£2.2k' }
    ],
    monthly_benefits: [
      { value: 1200, label: '£1.2k' },
      { value: 1800, label: '£1.8k' },
      { value: 2200, label: '£2.2k' }
    ],
    daily_living_points: [
      { value: 0, label: '0 pts' },
      { value: 8, label: '8 pts' },
      { value: 12, label: '12 pts' }
    ],
    mobility_points: [
      { value: 0, label: '0 pts' },
      { value: 8, label: '8 pts' },
      { value: 12, label: '12 pts' }
    ],
    weeks_off: [
      { value: 1, label: '1 wk' },
      { value: 4, label: '4 wks' },
      { value: 12, label: '12 wks' },
      { value: 28, label: '28 wks' }
    ],
    average_weekly_earnings: [
      { value: 250, label: '£250' },
      { value: 420, label: '£420' },
      { value: 600, label: '£600' }
    ]
  };
  var PRESETS_BY_FORMULA = {
    universal_credit: [
      { label: 'Single renter', values: { household: 'single', earnings: 900, savings: 0, housing_cost: 700, children: 0, age_band: '25_plus', childcare_cost: 0, health: 'none', first_child_pre_2017: false } },
      { label: 'Family + childcare', values: { household: 'couple', earnings: 1600, savings: 0, housing_cost: 950, children: 2, age_band: '25_plus', childcare_cost: 450, health: 'none', first_child_pre_2017: true } },
      { label: 'Savings over £6k', values: { household: 'single', earnings: 900, savings: 9000, housing_cost: 700, children: 0, age_band: '25_plus', childcare_cost: 0, health: 'none', first_child_pre_2017: false } }
    ],
    child_benefit: [
      { label: '1 child', values: { children: 1 } },
      { label: '2 children', values: { children: 2 } },
      { label: '3 children', values: { children: 3 } }
    ],
    hicbc: [
      { label: 'Threshold', values: { children: 2, adjusted_net_income: 60000 } },
      { label: 'Mid taper', values: { children: 2, adjusted_net_income: 70000 } },
      { label: 'Full charge', values: { children: 2, adjusted_net_income: 80000 } }
    ],
    pension_credit: [
      { label: 'Single pensioner', values: { household: 'single', weekly_income: 180, savings: 0, severe_disability: false, carer: false } },
      { label: 'Couple', values: { household: 'couple', weekly_income: 250, savings: 5000, severe_disability: false, carer: false } },
      { label: 'Savings over £10k', values: { household: 'single', weekly_income: 160, savings: 12000, severe_disability: false, carer: false } }
    ],
    pip: [
      { label: 'No award', values: { daily_living_points: 0, mobility_points: 0 } },
      { label: 'Standard rates', values: { daily_living_points: 8, mobility_points: 8 } },
      { label: 'Enhanced rates', values: { daily_living_points: 12, mobility_points: 12 } }
    ],
    council_tax_reduction: [
      { label: 'Low income', values: { monthly_council_tax: 180, monthly_income: 900, savings: 0, on_means_tested_benefit: false, single_adult: false, on_guarantee_pension_credit: false } },
      { label: 'Single adult', values: { monthly_council_tax: 180, monthly_income: 1500, savings: 0, on_means_tested_benefit: false, single_adult: true, on_guarantee_pension_credit: false } },
      { label: 'Savings over £16k', values: { monthly_council_tax: 180, monthly_income: 900, savings: 17000, on_means_tested_benefit: false, single_adult: false, on_guarantee_pension_credit: false } }
    ],
    housing_benefit: [
      { label: 'Legacy tenant', values: { weekly_rent: 140, weekly_income: 120, savings: 0, legacy_claimant: true, pension_age: false, spare_room: false } },
      { label: 'Pension-age', values: { weekly_rent: 160, weekly_income: 180, savings: 12000, legacy_claimant: true, pension_age: true, spare_room: false } },
      { label: 'Spare room', values: { weekly_rent: 140, weekly_income: 160, savings: 0, legacy_claimant: true, pension_age: false, spare_room: true } }
    ],
    benefit_cap: [
      { label: 'Outside London family', values: { monthly_benefits: 1900, household: 'couple', inside_london: false } },
      { label: 'London family', values: { monthly_benefits: 2400, household: 'couple', inside_london: true } },
      { label: 'Single adult', values: { monthly_benefits: 1300, household: 'single_adult', inside_london: false } }
    ],
    ssp: [
      { label: '2 weeks off', values: { average_weekly_earnings: 420, weeks_off: 2 } },
      { label: '4 weeks off', values: { average_weekly_earnings: 420, weeks_off: 4 } },
      { label: '12 weeks off', values: { average_weekly_earnings: 420, weeks_off: 12 } }
    ],
    maternity_comparison: [
      { label: 'Eligible for both', values: { average_weekly_earnings: 380, employed_long_enough: true, employed_or_self_employed_long_enough: true } },
      { label: 'MA only', values: { average_weekly_earnings: 260, employed_long_enough: false, employed_or_self_employed_long_enough: true } },
      { label: 'Lower earnings', values: { average_weekly_earnings: 180, employed_long_enough: true, employed_or_self_employed_long_enough: true } }
    ],
    esa: [
      { label: 'Work-related', values: { group: 'work_related', private_pension_weekly: 0, has_recent_ni_record: true } },
      { label: 'Support group', values: { group: 'support', private_pension_weekly: 0, has_recent_ni_record: true } },
      { label: 'Pension deduction', values: { group: 'support', private_pension_weekly: 140, has_recent_ni_record: true } }
    ]
  };

  function fmtMoney(n, decimals) {
    var abs = Math.abs(Number(n) || 0);
    var places = typeof decimals === 'number' ? decimals : 2;
    var out = abs.toLocaleString('en-GB', { minimumFractionDigits: places, maximumFractionDigits: places });
    return (n < 0 ? '-£' : '£') + out;
  }

  function fmtCompactMoney(n) {
    return fmtMoney(n, Math.abs(n) >= 100 ? 0 : 2);
  }

  function roundMoney(n) {
    return Math.round((Number(n || 0) + 1e-9) * 100) / 100;
  }

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function findFieldConfig(name) {
    for (var i = 0; i < FIELDS.length; i++) {
      if (FIELDS[i].name === name) return FIELDS[i];
    }
    return null;
  }

  function getSelectLabel(fieldName, value) {
    var field = findFieldConfig(fieldName);
    if (!field || !field.options) return String(value);
    for (var i = 0; i < field.options.length; i++) {
      if (field.options[i].value === value) return field.options[i].label;
    }
    return String(value);
  }

  function findBreakdownValue(d, label) {
    var rows = d.breakdown || [];
    for (var i = 0; i < rows.length; i++) {
      if (rows[i][0] === label) return Number(rows[i][1]) || 0;
    }
    return 0;
  }

  function readInputs() {
    var inp = {};
    FIELDS.forEach(function (f) {
      var el = form.elements[f.name];
      if (!el) return;
      if (f.type === 'boolean') {
        inp[f.name] = !!el.checked;
      } else if (f.type === 'number') {
        var v = parseFloat(String(el.value).replace(/[,£]/g, ''));
        inp[f.name] = isNaN(v) ? (f['default'] || 0) : v;
      } else {
        inp[f.name] = el.value || f['default'] || '';
      }
    });
    return inp;
  }

  function setInputValue(name, value) {
    var field = findFieldConfig(name);
    var el = form.elements[name];
    if (!field || !el) return;
    if (field.type === 'boolean') {
      el.checked = !!value;
    } else {
      el.value = value;
    }
  }

  function updateChoiceState() {
    document.querySelectorAll('.field-choices').forEach(function (wrap) {
      var name = wrap.getAttribute('data-choices-for');
      var el = form.elements[name];
      if (!el) return;
      var current = el.type === 'checkbox' ? String(!!el.checked) : String(el.value);
      wrap.querySelectorAll('.choice-chip').forEach(function (chip) {
        chip.classList.toggle('is-active', chip.getAttribute('data-value') === current);
      });
    });
  }

  function renderFieldChoices() {
    FIELDS.forEach(function (field) {
      var wrap = document.querySelector('[data-choices-for="' + field.name + '"]');
      if (!wrap) return;
      var choices = FIELD_QUICK_CHOICES[field.name];
      if (!choices && field.type === 'select' && Array.isArray(field.options) && field.options.length <= 4) {
        choices = field.options.map(function (option) {
          return { value: option.value, label: option.label };
        });
      }
      if (!choices || !choices.length) {
        wrap.innerHTML = '';
        return;
      }
      wrap.innerHTML = choices.map(function (choice) {
        return '<button type="button" class="choice-chip" data-field="' + esc(field.name) + '" data-value="' + esc(String(choice.value)) + '">' + esc(choice.label) + '</button>';
      }).join('');
    });

    document.querySelectorAll('.choice-chip').forEach(function (chip) {
      chip.addEventListener('click', function () {
        var name = chip.getAttribute('data-field');
        var value = chip.getAttribute('data-value');
        var field = findFieldConfig(name);
        if (!field) return;
        setInputValue(name, field.type === 'number' ? Number(value) : value);
        updateChoiceState();
        recalculate();
      });
    });

    updateChoiceState();
  }

  function presetMatchesInputs(preset, inputs) {
    if (!preset || !preset.values) return false;
    for (var key in preset.values) {
      if (String(inputs[key]) !== String(preset.values[key])) return false;
    }
    return true;
  }

  function updatePresetState() {
    var current = readInputs();
    document.querySelectorAll('#preset-chip-group button').forEach(function (chip, idx) {
      var preset = (PRESETS_BY_FORMULA[FORMULA] || [])[idx];
      chip.classList.toggle('qa-active', presetMatchesInputs(preset, current));
    });
  }

  function renderPresets() {
    var wrap = document.getElementById('preset-chip-group');
    var presets = PRESETS_BY_FORMULA[FORMULA] || [];
    if (!wrap) return;
    if (!presets.length) {
      wrap.hidden = true;
      return;
    }
    wrap.hidden = false;
    wrap.innerHTML = presets.map(function (preset, idx) {
      return '<button type="button" data-preset-index="' + idx + '">' + esc(preset.label) + '</button>';
    }).join('');
    wrap.querySelectorAll('button').forEach(function (chip) {
      chip.addEventListener('click', function () {
        var preset = presets[Number(chip.getAttribute('data-preset-index'))];
        if (!preset || !preset.values) return;
        Object.keys(preset.values).forEach(function (key) {
          setInputValue(key, preset.values[key]);
        });
        var moreFields = document.getElementById('moreFields');
        var moreToggle = document.getElementById('moreToggle');
        if (moreFields && moreToggle) {
          var needsAdvanced = Object.keys(preset.values).some(function (key) {
            return !!document.querySelector('#moreFields [name="' + key + '"]');
          });
          if (needsAdvanced) {
            moreFields.classList.add('open');
            moreToggle.classList.add('open');
            moreToggle.firstChild.textContent = 'Fewer options';
          }
        }
        updateChoiceState();
        updatePresetState();
        recalculate();
      });
    });
    updatePresetState();
  }

  function updateDonut(legend) {
    var cumulative = 0;
    var total = legend.reduce(function (sum, item) { return sum + Math.max(0, Number(item.value) || 0); }, 0);
    if (total <= 0) {
      SEG_IDS.forEach(function (id) {
        var seg = document.getElementById(id);
        if (seg) {
          seg.style.strokeDasharray = '0 452';
          seg.style.strokeDashoffset = '0';
        }
      });
      return;
    }
    legend.forEach(function (item, idx) {
      var seg = document.getElementById(SEG_IDS[idx]);
      if (!seg) return;
      var value = Math.max(0, Number(item.value) || 0);
      var fraction = value / total;
      var dash = fraction * CIRC * 0.92;
      var gap = CIRC - dash;
      var offset = -(cumulative / total * CIRC * 0.92);
      seg.style.stroke = item.color;
      seg.style.strokeDasharray = dash + ' ' + gap;
      seg.style.strokeDashoffset = offset;
      cumulative += value;
    });
    for (var i = legend.length; i < SEG_IDS.length; i++) {
      var extra = document.getElementById(SEG_IDS[i]);
      if (extra) {
        extra.style.strokeDasharray = '0 452';
        extra.style.strokeDashoffset = '0';
      }
    }
  }

  function bindLegendHover() {
    document.querySelectorAll('#breakdownLegend .legend-row').forEach(function (row, idx) {
      row.addEventListener('mouseenter', function () {
        document.querySelectorAll('.donut-seg').forEach(function (seg, segIdx) {
          seg.classList.toggle('seg-focus', segIdx === idx);
          seg.classList.toggle('seg-muted', segIdx !== idx);
        });
        row.classList.add('legend-active');
      });
      row.addEventListener('mouseleave', function () {
        document.querySelectorAll('.donut-seg').forEach(function (seg) {
          seg.classList.remove('seg-focus');
          seg.classList.remove('seg-muted');
        });
        row.classList.remove('legend-active');
      });
    });
  }

  function buildResultHighlights(d, inputs) {
    if (FORMULA === 'universal_credit') {
      var savingsDeduction = Math.abs(findBreakdownValue(d, 'Savings deduction'));
      return [
        { label: 'Monthly award', value: fmtMoney(d.primary_amount), tone: 'primary' },
        { label: 'Annual view', value: fmtMoney(d.secondary_amount), tone: 'standard' },
        { label: 'Savings entered', value: fmtMoney(inputs.savings || 0), tone: 'standard' },
        { label: 'Tariff income/month', value: fmtMoney(savingsDeduction), tone: 'standard' },
        { label: 'Capital status', value: (inputs.savings || 0) >= 16000 ? 'Over £16,000 entered' : 'Below £16,000 limit', tone: 'muted' }
      ];
    }
    if (FORMULA === 'child_benefit') {
      var monthlyChildBenefit = roundMoney((d.primary_amount || 0) * 52 / 12);
      return [
        { label: 'Weekly amount', value: fmtMoney(d.primary_amount), tone: 'primary' },
        { label: 'Monthly equivalent', value: fmtMoney(monthlyChildBenefit), tone: 'standard' },
        { label: 'Annual amount', value: fmtMoney(d.secondary_amount), tone: 'standard' },
        { label: 'Children used', value: String(Math.max(0, Math.floor(inputs.children || 0))), tone: 'muted' }
      ];
    }
    if (FORMULA === 'pip') {
      var daily = findBreakdownValue(d, 'Daily living component');
      var mobility = findBreakdownValue(d, 'Mobility component');
      var monthlyPip = roundMoney((d.primary_amount || 0) * 52 / 12);
      function pipComponentLabel(rate, component) {
        if (rate <= 0) return 'No ' + component + ' award';
        if (rate >= 100) return 'Enhanced (' + fmtMoney(rate) + '/wk)';
        if (rate >= 30) return 'Standard (' + fmtMoney(rate) + '/wk)';
        return fmtMoney(rate) + '/wk';
      }
      return [
        { label: 'Daily living award', value: pipComponentLabel(daily, 'daily living'), tone: 'standard' },
        { label: 'Mobility award', value: pipComponentLabel(mobility, 'mobility'), tone: 'standard' },
        { label: 'Weekly amount', value: fmtMoney(d.primary_amount), tone: 'primary' },
        { label: 'Monthly equivalent', value: fmtMoney(monthlyPip), tone: 'standard' },
        { label: 'Annual equivalent', value: fmtMoney(d.secondary_amount), tone: 'standard' }
      ];
    }
    if (FORMULA === 'benefit_cap') {
      return [
        { label: 'Amount over cap', value: fmtMoney(d.primary_amount), tone: 'primary' },
        { label: 'Capped total', value: fmtMoney(d.secondary_amount), tone: 'standard' },
        { label: 'Cap used', value: fmtMoney(findBreakdownValue(d, 'Monthly cap used')), tone: 'standard' },
        { label: 'Household used', value: getSelectLabel('household', inputs.household), tone: 'muted' }
      ];
    }
    if (FORMULA === 'council_tax_reduction') {
      return [
        { label: 'Monthly help', value: fmtMoney(d.primary_amount), tone: 'primary' },
        { label: 'Annual help', value: fmtMoney(d.secondary_amount), tone: 'standard' },
        { label: 'Monthly bill used', value: fmtMoney(inputs.monthly_council_tax || 0), tone: 'standard' },
        { label: 'Reduction rate', value: Math.round(findBreakdownValue(d, 'Reduction percentage used')) + '%', tone: 'standard' },
        { label: 'Savings entered', value: fmtMoney(inputs.savings || 0), tone: 'muted' }
      ];
    }
    if (FORMULA === 'housing_benefit') {
      var monthlyHousingBenefit = roundMoney((d.primary_amount || 0) * 52 / 12);
      return [
        { label: 'Weekly support', value: fmtMoney(d.primary_amount), tone: 'primary' },
        { label: 'Monthly equivalent', value: fmtMoney(monthlyHousingBenefit), tone: 'standard' },
        { label: 'Annual equivalent', value: fmtMoney(d.secondary_amount), tone: 'standard' },
        { label: 'Weekly rent used', value: fmtMoney(inputs.weekly_rent || 0), tone: 'standard' },
        { label: 'Savings entered', value: fmtMoney(inputs.savings || 0), tone: 'muted' }
      ];
    }
    if (FORMULA === 'pension_credit') {
      var monthlyPensionCredit = roundMoney((d.primary_amount || 0) * 52 / 12);
      return [
        { label: 'Weekly amount', value: fmtMoney(d.primary_amount), tone: 'primary' },
        { label: 'Monthly equivalent', value: fmtMoney(monthlyPensionCredit), tone: 'standard' },
        { label: 'Annual amount', value: fmtMoney(d.secondary_amount), tone: 'standard' },
        { label: 'Savings entered', value: fmtMoney(inputs.savings || 0), tone: 'standard' },
        { label: 'Household used', value: getSelectLabel('household', inputs.household), tone: 'muted' }
      ];
    }
    return [
      { label: d.primary_label || 'Main estimate', value: fmtMoney(d.primary_amount), tone: 'primary' },
      { label: d.secondary_label || 'Secondary estimate', value: fmtMoney(d.secondary_amount), tone: 'standard' }
    ];
  }

  function renderHighlights(highlights) {
    var wrap = document.getElementById('result-facts');
    if (!wrap) return;
    wrap.innerHTML = highlights.map(function (item) {
      return '<div class="result-fact" data-tone="' + esc(item.tone || 'standard') + '">'
        + '<span class="result-fact-dot"></span>'
        + '<span class="result-fact-label">' + esc(item.label) + '</span>'
        + '<span class="result-fact-value">' + esc(item.value) + '</span>'
        + '</div>';
    }).join('');
  }

  function updateUI(d) {
    var el;
    el = document.getElementById('result-primary-chart');
    if (el) el.textContent = fmtCompactMoney(d.primary_amount);
    el = document.getElementById('result-kicker-chart');
    if (el) el.textContent = d.primary_label;
    el = document.getElementById('result-annual-chart');
    if (el) el.textContent = fmtCompactMoney(d.secondary_amount) + '/yr';

    var legend = d.visual && d.visual.legend ? d.visual.legend : [];
    el = document.getElementById('breakdownLegend');
    if (el) {
      el.innerHTML = legend.map(function (item) {
        return '<div class="legend-row">'
          + '<span class="legend-dot" style="background:' + esc(item.color) + '"></span>'
          + '<span class="legend-name">' + esc(item.label) + '</span>'
          + '<span class="legend-val">' + fmtMoney(item.value) + '</span>'
          + '</div>';
      }).join('');
    }

    updateDonut(legend);
    bindLegendHover();
    renderHighlights(buildResultHighlights(d, readInputs()));

    el = document.getElementById('result-breakdown');
    if (el) {
      el.innerHTML = (d.breakdown || []).map(function (pair) {
        var label = pair[0];
        var value = Number(pair[1]) || 0;
        var formatted = label.toLowerCase().indexOf('percentage') !== -1 ? Math.round(value) + '%' : fmtMoney(value);
        return '<div class="breakdown-row"><span>' + esc(label) + '</span><strong>' + esc(formatted) + '</strong></div>';
      }).join('');
    }

    el = document.getElementById('result-notes');
    if (el) {
      el.innerHTML = (d.notes || []).map(function (note) {
        return '<div class="note-item">' + esc(note) + '</div>';
      }).join('');
    }
  }

  function recalculate() {
    var d = window.CALC_ENGINE.calculate(FORMULA, readInputs());
    if (d) updateUI(d);
    updateChoiceState();
    updatePresetState();
  }

  form.querySelectorAll('input, select').forEach(function (el) {
    el.addEventListener('input', recalculate);
    el.addEventListener('change', recalculate);
  });

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    recalculate();
  });

  var moreToggle = document.getElementById('moreToggle');
  if (moreToggle) {
    moreToggle.addEventListener('click', function () {
      var fields = document.getElementById('moreFields');
      if (!fields) return;
      var open = fields.classList.toggle('open');
      moreToggle.classList.toggle('open', open);
      moreToggle.firstChild.textContent = open ? 'Fewer options' : 'More options';
    });
  }

  renderFieldChoices();
  renderPresets();
  renderHighlights(PAGE.initialHighlights || []);
  recalculate();
})();
