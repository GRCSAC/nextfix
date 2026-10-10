import _ from 'lodash';
export function render(s: string) { return _.template(s)(); }
