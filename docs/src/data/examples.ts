const files = import.meta.glob<string>('../../../examples/*.{yml,yaml}', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const examples = Object.entries(files)
  .map(([path, code]) => {
    const filename = path.split('/').at(-1)!;
    return { filename, slug: filename.replace(/\.ya?ml$/, ''), code };
  })
  .sort((a, b) => a.filename.localeCompare(b.filename));
